import os
from datetime import datetime
from functools import wraps
from urllib.parse import unquote
from flask import (
    Flask, render_template, jsonify, request,
    redirect, url_for, session
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import database as db
app = Flask(__name__)

@app.after_request
def _no_cache_html(response):
    try:
        ct = response.headers.get('Content-Type','')
        if ('text/html' in ct) or ('application/json' in ct):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
    except Exception:
        pass
    return response

# ── Rate Limiting & Cache ─────────────────────────────────────────────────────
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[]
)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})
# SECRET_KEY: usada pra assinar cookies de sessão.
# Em produção, defina via variável de ambiente FLASK_SECRET.
# Em dev, geramos uma chave estável a partir do filesystem.
_SECRET_FILE = os.path.join(os.path.dirname(__file__), '.secret_key')
if 'FLASK_SECRET' in os.environ:
    app.secret_key = os.environ['FLASK_SECRET']
else:
    if not os.path.exists(_SECRET_FILE):
        with open(_SECRET_FILE, 'wb') as f:
            f.write(os.urandom(32))
    with open(_SECRET_FILE, 'rb') as f:
        app.secret_key = f.read()
# Sessão dura 1 dia (mais seguro em máquinas compartilhadas do call center)
app.permanent_session_lifetime = 60 * 60 * 24
# Cookies de sessão mais seguros
_is_prod = 'FLASK_SECRET' in os.environ  # em produção a secret vem do ambiente
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,                # JS não acessa o cookie (anti-XSS)
    SESSION_COOKIE_SAMESITE='Lax',               # mitiga CSRF
    SESSION_COOKIE_SECURE=_is_prod,              # só envia o cookie por HTTPS em produção
)
# Em produção, força HTTPS (redireciona http -> https)
@app.before_request
def _force_https():
    if _is_prod and not request.is_secure:
        # Railway/proxies mandam o protocolo original neste header
        proto = request.headers.get('X-Forwarded-Proto', 'http')
        if proto != 'https':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)
UNITS_FALLBACK = ["PARÁ", "MANAUS", "MANOA", "SÃO LUIZ", "FORTALEZA", "AÇÃO"]
def _units():
    """Lista de unidades vinda do banco (Configuração > Unidades)."""
    try:
        return [u['nome'] for u in db.get_unidades()] or UNITS_FALLBACK
    except Exception:
        return UNITS_FALLBACK
# Prefixo de "unidade" reservada para Leads Recebidos (uma por unidade real).
# Reusa a tabela appointments (rows é JSON), então não precisa de migração.
# Ex.: os leads de PARÁ ficam armazenados sob a unit "LEADS::PARÁ".
LEADS_PREFIX = "LEADS::"
# "Unidade" reservada do Acompanhamento Unidades (uma linha por bairro, por dia)
ACOMP_UNIT = "ACOMP::GERAL"
# O fechamento do dia guarda o preenchimento aqui, no mesmo esquema.
FECH_UNIT  = "FECH::GERAL"
MONTHS = ["JANEIRO", "FEVEREIRO", "MARÇO", "ABRIL", "MAIO", "JUNHO",
          "JULHO", "AGOSTO", "SETEMBRO", "OUTUBRO", "NOVEMBRO", "DEZEMBRO"]
TIME_SLOTS = [
    {"key": "08-09", "label": "08H-09H"}, {"key": "09-10", "label": "09H-10H"},
    {"key": "10-11", "label": "10H-11H"}, {"key": "11-12", "label": "11H-12H"},
    {"key": "12-13", "label": "12H-13H"}, {"key": "13-14", "label": "13H-14H"},
    {"key": "14-15", "label": "14H-15H"}, {"key": "15-16", "label": "15H-16H"},
    {"key": "16-17", "label": "16H-17H"}, {"key": "17-18", "label": "17H-18H"},
    {"key": "18-19", "label": "18H-19H"}, {"key": "19-20", "label": "19H-20H"},
    {"key": "20-21", "label": "20H-21H"},
]
# ── Helpers ───────────────────────────────────────────────────────────────────
def _err(msg, code=400):
    return jsonify({'error': msg}), code
def _valid_date(s):
    if not isinstance(s, str):
        return False
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return True
    except ValueError:
        return False
def _valid_unit(u):
    return isinstance(u, str) and u in _units()
def _wants_json():
    """True se a request parece API (JSON). Usado para escolher 401 vs redirect."""
    if request.path.startswith('/api/'):
        return True
    accept = request.headers.get('Accept', '')
    return 'application/json' in accept
def login_required(view):
    """Bloqueia acesso a quem não estiver logado.
    Páginas: redireciona pra /login. APIs: retorna 401 JSON."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            if _wants_json():
                return _err('Não autenticado.', 401)
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapper
def admin_required(view):
    """Restringe a rota a usuários com papel 'admin'.
    Páginas: redireciona pro dashboard. APIs: retorna 403 JSON."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            if _wants_json():
                return _err('Não autenticado.', 401)
            return redirect(url_for('login', next=request.path))
        if session.get('role') != 'admin':
            if _wants_json():
                return _err('Acesso restrito a administradores.', 403)
            return redirect(url_for('dashboard'))
        return view(*args, **kwargs)
    return wrapper
# Disponibiliza o nome do usuário pra todos os templates
@app.context_processor
def inject_user():
    return {
        'current_user': session.get('username'),
        'current_user_id': session.get('user_id'),
        'current_role': session.get('role', 'all'),
    }
# ── Controle de acesso por equipe (agendamento x confirmacao) ────────────────
@app.before_request
def _team_access_guard():
    role = session.get('role', 'all')
    if role in ('all', 'admin', 'ambos'):
        return
    path = request.path or '/'
    if path.startswith('/static') or path.startswith('/login') or path == '/logout' or path.startswith('/api/stats_publicas'):
        return
    if role == 'confirmacao':
        allowed = (path.startswith('/confirmacao')
                   or path.startswith('/api/confirmacoes')
                   or (path.startswith('/api/appointments') and request.method == 'GET'))
        if not allowed:
            if _wants_json():
                return _err('Sem permissao para esta area.', 403)
            return redirect(url_for('confirmacao_analise'))
    elif role == 'agendamento':
        if path.startswith('/confirmacao') or path.startswith('/api/confirmacoes'):
            if _wants_json():
                return _err('Sem permissao para esta area.', 403)
            return redirect(url_for('dashboard'))
# ── Handlers globais de erro ──────────────────────────────────────────────────
@app.errorhandler(404)
def _not_found(_):
    if _wants_json():
        return _err('Recurso não encontrado', 404)
    return ('Página não encontrada', 404)
@app.errorhandler(500)
def _server_error(_):
    return _err('Erro interno do servidor', 500)
@app.errorhandler(429)
def _too_many_requests(e):
    """Mostra uma tela amigável quando o limite de tentativas é excedido."""
    if _wants_json():
        return _err('Muitas tentativas. Aguarde um momento e tente novamente.', 429)
    return render_template('rate_limit.html'), 429
# ── Login / Logout ────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    error = None
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        user = db.verify_password(username, password)
        if user:
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user.get('role', 'all')
            team = request.form.get('team', '')
            next_url = request.args.get('next', '')
            role = user.get('role', 'all')
            if team == 'confirmacao' or role == 'confirmacao':
                next_url = '/confirmacao'
            elif next_url and next_url.startswith('/'):
                pass
            else:
                next_url = url_for('dashboard')
            return redirect(next_url)
        error = 'Usuário ou senha incorretos.'
    return render_template('login.html', error=error)
@app.route('/api/stats_publicas')
def api_stats_publicas():
    """Rota PÚBLICA (sem login) para a landing. Devolve apenas 3 totais somados
    (leads, agendamentos, comparecimentos), sem expor nenhum dado individual."""
    try:
        return jsonify(db.get_stats_publicas())
    except Exception:
        # Se algo falhar, devolve zeros em vez de erro (a landing é pública)
        return jsonify({'leads': 0, 'agendamentos': 0, 'comparecimentos': 0})
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
# ── Páginas ───────────────────────────────────────────────────────────────────
@app.route('/')
def dashboard():
    # Entrada do site: visitante vê a landing institucional; logado vê o dashboard.
    if 'user_id' not in session:
        return render_template('landing.html')
    return render_template('dashboard.html')

@app.route('/site')
def site_institucional():
    # Pagina institucional acessivel mesmo logado (botao HOME)
    return render_template('landing.html')

@app.route('/google6b296435c4715c91.html')
def google_site_verification():
    return 'google-site-verification: google6b296435c4715c91.html', 200, {'Content-Type': 'text/html; charset=utf-8'}

@app.route('/sitemap.xml')
def sitemap_xml():
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
           '  <url><loc>https://connectingsales.com.br/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>\n'
           '</urlset>\n')
    return xml, 200, {'Content-Type': 'application/xml; charset=utf-8'}

@app.route('/robots.txt')
def robots_txt():
    txt = ('User-agent: *\n'
           'Disallow: /api/\n'
           'Disallow: /unit/\n'
           'Disallow: /employees\n'
           'Disallow: /users\n'
           'Disallow: /login\n'
           'Disallow: /confirmacao\n'
           'Sitemap: https://connectingsales.com.br/sitemap.xml\n')
    return txt, 200, {'Content-Type': 'text/plain; charset=utf-8'}
@app.route('/unit/<path:unit_name>')
@login_required
def unit_schedule(unit_name):
    unit_name = unquote(unit_name)
    if not _valid_unit(unit_name):
        return _err(f'Unidade inválida: {unit_name}', 404)
    return render_template('unit.html', unit=unit_name)
@app.route('/unit/<path:unit_name>/leads')
@login_required
def leads_page(unit_name):
    unit_name = unquote(unit_name)
    if not _valid_unit(unit_name):
        return _err(f'Unidade inválida: {unit_name}', 404)
    return render_template('leads.html', unit=unit_name)
@app.route('/employees')
@login_required
def employees_page():
    return render_template('employees.html')
@app.route('/users')
@admin_required
def users_page():
    return render_template('users.html')
# ── API: Usuários ─────────────────────────────────────────────────────────────
@app.route('/api/users', methods=['GET'])
@login_required
def api_list_users():
    return jsonify(db.list_users())
@app.route('/api/users', methods=['POST'])
@admin_required
def api_create_user():
    data = request.get_json(silent=True) or {}
    try:
        uid = db.create_user(data.get('username'), data.get('password'), data.get('role'))
        return jsonify({'id': uid, 'username': data['username'].strip()}), 201
    except ValueError as e:
        return _err(str(e))
@app.route('/api/users/<int:uid>', methods=['DELETE'])
@admin_required
def api_delete_user(uid):
    # Proteção: não permite deletar a si mesmo (evita ficar sem acesso)
    if uid == session.get('user_id'):
        return _err('Você não pode excluir o próprio usuário.', 403)
    # Proteção: precisa sobrar pelo menos 1 usuário
    if db.count_users() <= 1:
        return _err('Não é possível excluir o último usuário do sistema.', 403)
    db.delete_user(uid)
    return jsonify({'ok': True})
@app.route('/api/users/<int:uid>/password', methods=['POST'])
@login_required
def api_change_password(uid):
    # Admin pode trocar a senha de qualquer usuário.
    # Não-admin só pode trocar a PRÓPRIA senha.
    is_admin = session.get('role') == 'admin'
    if not is_admin and uid != session.get('user_id'):
        return _err('Você só pode alterar a sua própria senha.', 403)
    data = request.get_json(silent=True) or {}
    try:
        db.change_password(uid, data.get('password'))
        return jsonify({'ok': True})
    except ValueError as e:
        return _err(str(e))
# ── API: Funcionários ─────────────────────────────────────────────────────────
@app.route('/api/employees', methods=['GET'])
@login_required
def api_employees():
    unit = request.args.get('unit')
    if unit:
        unit = unquote(unit)
    if unit and not _valid_unit(unit):
        return _err(f'Unidade inválida: {unit}')
    active = request.args.get('active')
    active_bool = None
    if active == 'true':
        active_bool = True
    elif active == 'false':
        active_bool = False
    return jsonify(db.get_employees(unit=unit, active=active_bool))
@app.route('/api/employees', methods=['POST'])
@login_required
def api_create_employee():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    unit = data.get('unit')
    active = bool(data.get('active', True))
    funcao = (data.get('funcao') or 'ATENDENTE').strip().upper()
    if funcao not in ('ATENDENTE', 'LIDER'):
        funcao = 'ATENDENTE'
    if not name:
        return _err('Campo "name" é obrigatório')
    if not _valid_unit(unit):
        return _err(f'Campo "unit" inválido. Use um de: {_units()}')
    eid = db.create_employee(name, unit, active, funcao=funcao)
    return jsonify({'id': eid, 'name': name, 'unit': unit, 'active': active, 'funcao': funcao}), 201
@app.route('/api/employees/<int:eid>', methods=['DELETE'])
@login_required
def api_delete_employee(eid):
    hard = request.args.get('hard') == 'true'
    if hard:
        db.delete_employee_hard(eid)
    else:
        db.deactivate_employee(eid)
    return jsonify({'ok': True, 'hard': hard})

@app.route('/api/employees/rename', methods=['POST'])
@login_required
def api_rename_employee():
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(db.renomear_funcionario(data.get('de'), data.get('para')))
    except ValueError as e:
        return _err(str(e))
# ── Webhook: avisa um sistema externo a cada salvamento do Hora a Hora ────────
# Ligado so por ambiente (Easypanel > connecting2 > Environment):
#   WEBHOOK_URL       para onde mandar. Sem ela, nada e enviado.
#   WEBHOOK_SECRET    assina cada envio no cabecalho X-Connecting-Signature.
#   WEBHOOK_DEBOUNCE  segundos entre dois envios da mesma unidade/dia (30).
# O envio roda em segundo plano: quem esta digitando nunca espera o destino.
import hashlib
import hmac
import json as _json
import threading
import time
import urllib.request
_WH_ULTIMO = {}
_WH_TRAVA = threading.Lock()
def _wh_config():
    url = os.environ.get('WEBHOOK_URL', '').strip()
    if not url:
        return None
    try:
        espera = int(os.environ.get('WEBHOOK_DEBOUNCE', '30'))
    except (TypeError, ValueError):
        espera = 30
    return {'url': url,
            'segredo': os.environ.get('WEBHOOK_SECRET', '').strip(),
            'espera': max(0, espera)}
def _wh_retrato(unit, date, leader, rows):
    """O dia inteiro daquela unidade, ja somado — o destino nao precisa
    entender o formato interno do Hora a Hora."""
    por_hora = {}
    por_pessoa = []
    total = 0
    for r in (rows or []):
        if not isinstance(r, dict):
            continue
        nome = str(r.get('name') or '').strip()
        if not nome:
            continue                      # linha em branco nao vira pessoa
        slots = r.get('slots') or {}
        soma = 0
        for s in TIME_SLOTS:
            try:
                v = int(float(slots.get(s['key']) or 0))
            except (TypeError, ValueError):
                continue                  # texto no campo nao quebra o envio
            if v:
                por_hora[s['key']] = por_hora.get(s['key'], 0) + v
                soma += v
        try:
            soma += int(float(r.get('inclusao') or 0))
        except (TypeError, ValueError):
            pass
        por_pessoa.append({'nome': nome,
                           'lider': str(r.get('leader') or leader or ''),
                           'total': soma})
        total += soma
    por_pessoa.sort(key=lambda p: (-p['total'], p['nome']))
    meta_dia = 0
    try:
        for m in (db.get_metas(int(date[0:4]), int(date[5:7])) or []):
            if (m.get('unidade') or '') == unit and not (m.get('bairro') or ''):
                meta_dia = int(float(m.get('meta_dia') or 0))
                break
    except (TypeError, ValueError, KeyError):
        pass
    return {'evento': 'agendamento.salvo',
            'unidade': unit,
            'data': date,
            'lider': leader or '',
            'total_agendamentos': total,
            'por_hora': por_hora,
            'por_pessoa': por_pessoa,
            'meta_dia': meta_dia,
            'falta_para_meta': max(0, meta_dia - total),
            'enviado_em': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}
def _wh_envia(cfg, corpo):
    dados = _json.dumps(corpo, ensure_ascii=False).encode('utf-8')
    cab = {'Content-Type': 'application/json; charset=utf-8',
           'User-Agent': 'connecting-webhook/1'}
    if cfg['segredo']:
        cab['X-Connecting-Signature'] = hmac.new(
            cfg['segredo'].encode('utf-8'), dados, hashlib.sha256).hexdigest()
    pedido = urllib.request.Request(cfg['url'], data=dados, headers=cab,
                                    method='POST')
    try:
        with urllib.request.urlopen(pedido, timeout=8):
            pass
    except Exception as e:
        print('[webhook] falhou:', e, flush=True)
def disparar_webhook(unit, date, leader, rows):
    """Nunca levanta erro: se o webhook falhar, o salvamento ja esta feito."""
    try:
        cfg = _wh_config()
        if not cfg:
            return
        if unit.startswith(LEADS_PREFIX) or unit in (
                ACOMP_UNIT, LEADSAG_UNIT, FECH_UNIT, LEADSHH_UNIT):
            return                        # unidade reservada nao e agendamento
        chave = unit + '|' + date
        agora = time.time()
        with _WH_TRAVA:
            if agora - _WH_ULTIMO.get(chave, 0) < cfg['espera']:
                return                    # a tela salva a cada 1,2s digitando
            _WH_ULTIMO[chave] = agora
        corpo = _wh_retrato(unit, date, leader, rows)
        threading.Thread(target=_wh_envia, args=(cfg, corpo),
                         daemon=True).start()
    except Exception as e:
        print('[webhook] erro ao preparar:', e, flush=True)
# ── API: Agendamentos ─────────────────────────────────────────────────────────
@app.route('/api/appointments', methods=['GET'])
@login_required
def api_appointments():
    date = request.args.get('date')
    year = request.args.get('year')
    month = request.args.get('month')
    unit = request.args.get('unit')
    if unit and not _valid_unit(unit):
        return _err(f'Unidade inválida: {unit}')
    if date:
        if not _valid_date(date):
            return _err('Parâmetro "date" inválido. Use YYYY-MM-DD.')
        appts = db.get_appointments_by_date(date)
    elif year and month:
        try:
            y = int(year)
            m = int(month)
            if not (1 <= m <= 12) or not (1900 <= y <= 2999):
                raise ValueError
        except (TypeError, ValueError):
            return _err('Parâmetros "year"/"month" inválidos.')
        appts = db.get_appointments_by_month(y, m)
    else:
        return _err('Informe "date" (YYYY-MM-DD) ou "year"+"month".')
    # Nunca expõe as "unidades" reservadas (Leads e Acompanhamento) nos agendamentos nem no dashboard
    appts = [a for a in appts
             if not a['unit'].startswith(LEADS_PREFIX)
             and a['unit'] != ACOMP_UNIT and a['unit'] != LEADSAG_UNIT
             and a['unit'] != FECH_UNIT and a['unit'] != LEADSHH_UNIT]
    if unit:
        appts = [a for a in appts if a['unit'] == unit]
    return jsonify(appts)
@app.route('/api/appointments/<unit>/<date>', methods=['GET'])
@login_required
def api_get_appointment(unit, date):
    unit = unquote(unit)
    if not _valid_unit(unit):
        return _err(f'Unidade inválida: {unit}')
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    appt = db.get_appointment(unit, date)
    return jsonify(appt or {})
@app.route('/api/appointments/<unit>/<date>', methods=['POST'])
@login_required
def api_save_appointment(unit, date):
    unit = unquote(unit)
    if not _valid_unit(unit):
        return _err(f'Unidade inválida: {unit}')
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    data = request.get_json(silent=True) or {}
    leader = data.get('leader', '')
    rows = data.get('rows', [])
    if not isinstance(leader, str):
        return _err('Campo "leader" deve ser string.')
    if not isinstance(rows, list):
        return _err('Campo "rows" deve ser lista.')
    db.upsert_appointment(unit, date, leader, rows)
    disparar_webhook(unit, date, leader, rows)
    return jsonify({'ok': True})
@app.route('/api/appointments/<unit>/<date>/comparecimento', methods=['POST'])
@login_required
def api_save_comparecimento(unit, date):
    unit = unquote(unit)
    if not _valid_unit(unit):
        return _err(f'Unidade inválida: {unit}')
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    data = request.get_json(silent=True) or {}
    comp = data.get('comparecimento_data', {})
    if not isinstance(comp, dict):
        return _err('Campo "comparecimento_data" deve ser objeto.')
    db.update_comparecimento(unit, date, comp)
    return jsonify({'ok': True})
@app.route('/api/appointments/<unit>/<date>', methods=['DELETE'])
@login_required
def api_clear_appointment(unit, date):
    unit = unquote(unit)
    if not _valid_unit(unit):
        return _err(f'Unidade inválida: {unit}')
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    db.clear_appointment(unit, date)
    return jsonify({'ok': True})
# ── API: Leads Recebidos (reusa appointments com unidade reservada por unidade) ──
@app.route('/api/leads/<unit>/<date>', methods=['GET'])
@login_required
def api_get_leads(unit, date):
    unit = unquote(unit)
    if not _valid_unit(unit):
        return _err(f'Unidade inválida: {unit}')
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    appt = db.get_appointment(LEADS_PREFIX + unit, date)
    return jsonify(appt or {})
@app.route('/api/leads/<unit>/<date>', methods=['POST'])
@login_required
def api_save_leads(unit, date):
    unit = unquote(unit)
    if not _valid_unit(unit):
        return _err(f'Unidade inválida: {unit}')
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    data = request.get_json(silent=True) or {}
    leader = data.get('leader', '')
    rows = data.get('rows', [])
    if not isinstance(leader, str):
        return _err('Campo "leader" deve ser string.')
    if not isinstance(rows, list):
        return _err('Campo "rows" deve ser lista.')
    db.upsert_appointment(LEADS_PREFIX + unit, date, leader, rows)
    return jsonify({'ok': True})
@app.route('/api/leads/<unit>/<date>', methods=['DELETE'])
@login_required
def api_clear_leads(unit, date):
    unit = unquote(unit)
    if not _valid_unit(unit):
        return _err(f'Unidade inválida: {unit}')
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    db.clear_appointment(LEADS_PREFIX + unit, date)
    return jsonify({'ok': True})
# ── API: Constantes ───────────────────────────────────────────────────────────
# Carimbo da versao publicada. Sai da data dos arquivos, e nao do momento em que
# o processo subiu: assim os dois workers do Gunicorn devolvem o MESMO valor.
# Se fosse a hora de inicio, cada worker teria o seu e a tela ficaria
# recarregando em looping, alternando entre os dois.
def _versao_app():
    base = os.path.dirname(os.path.abspath(__file__))
    alvos = [os.path.abspath(__file__),
             os.path.join(base, 'templates', 'dashboard.html'),
             os.path.join(base, 'templates', 'base.html'),
             os.path.join(base, 'static', 'style.css')]
    marcas = []
    for p in alvos:
        try:
            marcas.append(int(os.path.getmtime(p)))
        except OSError:
            pass
    return str(max(marcas)) if marcas else '0'

VERSAO_APP = _versao_app()
# ── Resumo de Agendamentos do dia (Hora a Hora) ─────────────────────────────
# Rota enxuta: devolve so nome e total de cada TMK, por unidade. Feita para a
# tela do Resumo Geral se atualizar sozinha sem rebaixar o dashboard inteiro.
@app.route('/api/agendamentos_dia', methods=['GET'])
@login_required
def api_agendamentos_dia():
    """Resumo do Hora a Hora por unidade e pessoa.

    Com "date" devolve o dia; com "ano"+"mes" devolve o mes inteiro somado
    por pessoa. O Resumo Geral chama um ou outro conforme o filtro do topo.
    A meta do dia e a do mes vao nas duas respostas — quem escolhe qual usar
    e a tela, porque e ela que sabe o que esta mostrando.
    """
    date = request.args.get('date')
    if date:
        if not _valid_date(date):
            return _err('Data invalida. Use YYYY-MM-DD.')
        registros = db.get_appointments_by_date(date)
        ano, mes  = int(date[0:4]), int(date[5:7])
        periodo   = 'dia'
    else:
        try:
            ano = int(request.args.get('ano'))
            mes = int(request.args.get('mes'))
        except (TypeError, ValueError):
            return _err('Informe "date" (YYYY-MM-DD) ou "ano"+"mes".')
        if not (1 <= mes <= 12) or not (1900 <= ano <= 2999):
            return _err('Ano ou mes fora do intervalo.')
        registros = db.get_appointments_by_month(ano, mes)
        date      = ''
        periodo   = 'mes'

    validas = _units()
    conj = set(validas)
    por_unidade = {u: {} for u in validas}

    for a in (registros or []):
        unit = a.get('unit') or ''
        if unit not in conj:
            continue
        alvo = por_unidade[unit]
        for r in (a.get('rows') or []):
            if not isinstance(r, dict):
                continue
            nome = (r.get('name') or '').strip()
            if not nome:
                continue
            slots = r.get('slots') or {}
            tot = 0
            for s in TIME_SLOTS:
                try:
                    tot += int(float(slots.get(s['key']) or 0))
                except (TypeError, ValueError):
                    pass
            try:
                tot += int(float(r.get('inclusao') or 0))
            except (TypeError, ValueError):
                pass
            alvo[nome] = alvo.get(nome, 0) + tot

    # Meta de agendamentos do dia, por unidade (campo META AGEND DIA).
    # Linhas de bairro nao entram: a caixa e da unidade inteira.
    meta_de = {}
    meta_mes_de = {}
    try:
        for m in (db.get_metas(ano, mes) or []):
            if not (m.get('bairro') or ''):
                u = m.get('unidade') or ''
                try:
                    meta_de[u] = int(float(m.get('meta_dia') or 0))
                except (TypeError, ValueError):
                    pass
                try:
                    meta_mes_de[u] = int(float(m.get('meta_agend') or 0))
                except (TypeError, ValueError):
                    pass
    except Exception:
        pass

    out = []
    for u in validas:
        pessoas = [{'nome': n, 'ags': v} for n, v in por_unidade[u].items()]
        pessoas.sort(key=lambda p: (-p['ags'], p['nome']))
        out.append({
            'unidade': u,
            'total': sum(p['ags'] for p in pessoas),
            'meta_dia': meta_de.get(u, 0),
            'meta_mes': meta_mes_de.get(u, 0),
            'pessoas': pessoas,
        })

    return jsonify({'date': date, 'periodo': periodo, 'ano': ano, 'mes': mes,
                    'v': VERSAO_APP, 'unidades': out})
@app.route('/api/constants')
@login_required
def api_constants():
    return jsonify({'units': _units(), 'months': MONTHS, 'time_slots': TIME_SLOTS})
# Chaves de leads que entraram — montadas a partir das fontes cadastradas.
# A fonte ANTIGOS continua sendo lançada e exibida, mas NÃO soma no total de leads.
FONTES_FORA_DO_TOTAL = {'antigos'}
LEAD_KEYS_FALLBACK = ['wbp_lead', 'vbot_lead', 'mkt_lead', 'whats_lead', 'mabe_lead']
def _lead_keys():
    """Chaves que somam no total de leads recebidos."""
    try:
        chaves = [f"{f['chave']}_lead" for f in db.get_fontes()
                  if f['chave'] not in FONTES_FORA_DO_TOTAL]
        return chaves or LEAD_KEYS_FALLBACK
    except Exception:
        return LEAD_KEYS_FALLBACK
@app.route('/api/leads_totais', methods=['GET'])
@login_required
def api_leads_totais():
    """Retorna o total de leads recebidos por unidade (dia ou mês).
    Usado no Resumo Geral para mostrar Leads -> Agendamentos -> Comparecimentos -> %."""
    date = request.args.get('date')
    year = request.args.get('year')
    month = request.args.get('month')
    if date:
        if not _valid_date(date):
            return _err('Parâmetro "date" inválido. Use YYYY-MM-DD.')
        appts = db.get_appointments_by_date(date)
    elif year and month:
        try:
            y = int(year)
            m = int(month)
            if not (1 <= m <= 12) or not (1900 <= y <= 2999):
                raise ValueError
        except (TypeError, ValueError):
            return _err('Parâmetros "year"/"month" inválidos.')
        appts = db.get_appointments_by_month(y, m)
    else:
        return _err('Informe "date" (YYYY-MM-DD) ou "year"+"month".')
    # Soma os leads so das unidades reservadas LEADS::, por unidade real
    totais = {u: 0 for u in _units()}
    lead_keys = _lead_keys()
    for a in appts:
        unit = a['unit']
        if not unit.startswith(LEADS_PREFIX):
            continue
        unidade_real = unit[len(LEADS_PREFIX):]
        if unidade_real not in totais:
            continue
        for r in (a.get('rows') or []):
            lead_data = r.get('lead') or {}
            totais[unidade_real] += sum(int(lead_data.get(k) or 0) for k in lead_keys)
    return jsonify(totais)
@app.route('/api/leads_por_tmk', methods=['GET'])
@login_required
def api_leads_por_tmk():
    """Retorna o total de leads recebidos por TMK (nome), somando todas as unidades.
    Usado no Ranking de TMK do painel Extrair Dados."""
    date = request.args.get('date')
    year = request.args.get('year')
    month = request.args.get('month')
    if date:
        if not _valid_date(date):
            return _err('Parâmetro "date" inválido. Use YYYY-MM-DD.')
        appts = db.get_appointments_by_date(date)
    elif year and month:
        try:
            y = int(year)
            m = int(month)
            if not (1 <= m <= 12) or not (1900 <= y <= 2999):
                raise ValueError
        except (TypeError, ValueError):
            return _err('Parâmetros "year"/"month" inválidos.')
        appts = db.get_appointments_by_month(y, m)
    else:
        return _err('Informe "date" (YYYY-MM-DD) ou "year"+"month".')
    # Soma os leads por nome de TMK (apenas das "unidades" reservadas LEADS::)
    por_tmk = {}
    lead_keys = _lead_keys()
    for a in appts:
        unit = a['unit']
        if not unit.startswith(LEADS_PREFIX):
            continue
        for r in (a.get('rows') or []):
            nome = (r.get('name') or '').strip()
            if not nome:
                continue
            lead_data = r.get('lead') or {}
            total = sum(int(lead_data.get(k) or 0) for k in lead_keys)
            por_tmk[nome] = por_tmk.get(nome, 0) + total
    return jsonify(por_tmk)
def _role_allowed(*roles):
    user_role = session.get('role', 'all')
    return user_role in ('all', 'admin', 'ambos') or user_role in roles
ATENDENTES_FALLBACK = ['VIVIANE', 'DIELLEM', 'LIVYA', 'KEILANE', 'LUANE', 'MARIA']
def _atendentes():
    """Equipe de confirmacao vinda do banco (Configuracao > Equipe)."""
    try:
        return [a['nome'] for a in db.get_atendentes()] or ATENDENTES_FALLBACK
    except Exception:
        return ATENDENTES_FALLBACK
UNIDADES_CONF = {
    'MANAUS': ['MANAUS'],
    'MANOA': ['MANOA'],
    'PARÁ': ['ANANINDEUA','AUGUSTO MONTENEGRO','BRAGANÇA','CAPANEMA',
              'CAPITAO POÇO','CASTANHAL','CIDADE NOVA','JOSÉ BONIFÁCIO',
              'JURUNAS','MARABÁ','MARAMBAIA','SANTAREM','TELEGRAFO'],
    'FORTALEZA': ['FORTALEZA'],
    'SÃO LUIZ': ['SÃO LUIZ'],
}
def _norm_atendente(value):
    """Valida e normaliza o nome da atendente vindo da query string.
    Retorna o nome em maiúsculo se for válido, ou None caso contrário."""
    if not value:
        return None
    v = value.strip().upper()
    return v if v in _atendentes() else None
@app.route('/confirmacao')
@login_required
def confirmacao_analise():
    if not _role_allowed('confirmacao'):
        return redirect(url_for('dashboard'))
    return render_template('analise_confirmacao.html',
                           atendentes=_atendentes(),
                           unidades_conf=UNIDADES_CONF,
                           atendente=None)
@app.route('/confirmacao/<atendente>')
@login_required
def confirmacao_page(atendente=None):
    if not _role_allowed('confirmacao'):
        return redirect(url_for('dashboard'))
    if atendente:
        atendente = atendente.upper()
        if atendente not in _atendentes():
            return redirect(url_for('confirmacao_analise'))
    return render_template('confirmacao.html', atendente=atendente, atendentes=_atendentes())
@app.route('/api/confirmacoes', methods=['GET'])
@login_required
def api_list_confirmacoes():
    if not _role_allowed('confirmacao'):
        return _err('Sem permissão.', 403)
    mes       = request.args.get('mes')
    data_str  = request.args.get('data_str')
    tmk       = request.args.get('tmk')
    atendente = _norm_atendente(request.args.get('atendente'))
    # Validação server-side do TMK
    if tmk:
        if not isinstance(tmk, str):
            return _err('tmk deve ser uma string.')
        if len(tmk) > 200:
            return _err('tmk muito longo (máximo 200 caracteres).')
    return jsonify(db.get_confirmacoes(mes=mes, data_str=data_str, tmk=tmk, atendente=atendente))
@app.route('/api/confirmacoes/clear_day', methods=['DELETE'])
@login_required
def api_clear_day_confirmacoes():
    if not _role_allowed('confirmacao'):
        return _err('Sem permissão.', 403)
    data_str  = request.args.get('data_str')
    atendente = _norm_atendente(request.args.get('atendente'))
    if not data_str:
        return _err('Informe data_str.')
    db.clear_confirmacoes_dia(data_str, atendente=atendente)
    return jsonify({'ok': True})
@app.route('/api/confirmacoes', methods=['POST'])
@login_required
def api_create_confirmacao():
    if not _role_allowed('confirmacao'):
        return _err('Sem permissão.', 403)
    data = request.get_json(silent=True) or {}
    # Normaliza o atendente se vier informado
    at = _norm_atendente(data.get('atendente'))
    if at:
        data['atendente'] = at
    cid = db.create_confirmacao(data)
    return jsonify({'id': cid}), 201
@app.route('/api/confirmacoes/<int:cid>', methods=['PUT'])
@login_required
def api_update_confirmacao(cid):
    if not _role_allowed('confirmacao'):
        return _err('Sem permissão.', 403)
    data = request.get_json(silent=True) or {}
    db.update_confirmacao(cid, data)
    return jsonify({'ok': True})
@app.route('/api/confirmacoes/<int:cid>', methods=['DELETE'])
@login_required
def api_delete_confirmacao(cid):
    if not _role_allowed('confirmacao'):
        return _err('Sem permissão.', 403)
    db.delete_confirmacao(cid)
    return jsonify({'ok': True})
@app.route('/api/confirmacoes/bulk', methods=['POST'])
@login_required
def api_bulk_confirmacoes():
    if not _role_allowed('confirmacao'):
        return _err('Sem permissão.', 403)
    data = request.get_json(silent=True) or {}
    rows = data.get('rows', [])
    if not isinstance(rows, list):
        return _err('rows deve ser uma lista.')
    # Atendente do lote: aplica a mesma etiqueta a todas as linhas coladas.
    at = _norm_atendente(data.get('atendente'))
    if at:
        for r in rows:
            if isinstance(r, dict):
                r['atendente'] = at
    db.bulk_insert_confirmacoes(rows)
    return jsonify({'ok': True, 'count': len(rows)}), 201
# ── API: Metas ────────────────────────────────────────────────────────────────
@app.route('/api/metas', methods=['GET'])
@login_required
def api_get_metas():
    try:
        ano = int(request.args.get('ano'))
        mes = int(request.args.get('mes'))
    except (TypeError, ValueError):
        return _err('Informe ano e mes válidos.')
    if not (1 <= mes <= 12) or not (1900 <= ano <= 2999):
        return _err('Ano ou mês fora do intervalo.')
    return jsonify(db.get_metas(ano, mes))
@app.route('/api/metas', methods=['POST'])
@login_required
def api_save_metas():
    data = request.get_json(silent=True) or {}
    try:
        ano = int(data.get('ano'))
        mes = int(data.get('mes'))
    except (TypeError, ValueError):
        return _err('Informe ano e mes válidos.')
    if not (1 <= mes <= 12) or not (1900 <= ano <= 2999):
        return _err('Ano ou mês fora do intervalo.')
    metas = data.get('metas', [])
    if not isinstance(metas, list):
        return _err('metas deve ser uma lista.')
    # Valida unidades
    for m in metas:
        u = m.get('unidade')
        if u not in _units():
            return _err(f'Unidade inválida nas metas: {u}')
    db.bulk_upsert_metas(ano, mes, metas)
    return jsonify({'ok': True, 'count': len(metas)})

# ── Fontes de leads (Configuração) ───────────────────────────────────────────
@app.route('/configuracao/fontes')
@admin_required
def fontes_page():
    return render_template('fontes.html')
@app.route('/api/fontes', methods=['GET'])
@login_required
def api_list_fontes():
    return jsonify(db.get_fontes())
@app.route('/api/fontes', methods=['POST'])
@admin_required
def api_create_fonte():
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(db.create_fonte(data.get('nome'), data.get('chave'))), 201
    except ValueError as e:
        return _err(str(e))
@app.route('/api/fontes/<int:fid>', methods=['DELETE'])
@admin_required
def api_delete_fonte(fid):
    db.delete_fonte(fid)
    return jsonify({'ok': True})
# ── Unidades (Configuração) ──────────────────────────────────────────────────
@app.route('/configuracao/unidades')
@admin_required
def unidades_page():
    return render_template('unidades.html')
@app.route('/api/unidades', methods=['GET'])
@login_required
def api_list_unidades():
    return jsonify(db.get_unidades())
@app.route('/api/unidades', methods=['POST'])
@admin_required
def api_create_unidade():
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(db.create_unidade(data.get('nome'), data.get('regiao'))), 201
    except ValueError as e:
        return _err(str(e))
@app.route('/api/unidades/<int:uid>/regiao', methods=['POST'])
@admin_required
def api_set_regiao(uid):
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(db.set_regiao_unidade(uid, data.get('regiao')))
    except ValueError as e:
        return _err(str(e))
@app.route('/api/unidades/<int:uid>/nome', methods=['POST'])
@admin_required
def api_rename_unidade(uid):
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(db.renomear_unidade(uid, data.get('nome')))
    except ValueError as e:
        return _err(str(e))
@app.route('/api/unidades/ordem', methods=['POST'])
@admin_required
def api_ordem_unidades():
    data = request.get_json(silent=True) or {}
    ids = data.get('ids') or []
    if not isinstance(ids, list) or not ids:
        return _err('Lista de unidades vazia.')
    try:
        return jsonify(db.reordenar_unidades(ids))
    except ValueError as e:
        return _err(str(e))
@app.route('/api/regioes', methods=['GET'])
@login_required
def api_list_regioes():
    return jsonify(db.get_regioes())
@app.route('/api/unidades/<int:uid>', methods=['DELETE'])
@admin_required
def api_delete_unidade(uid):
    alvo = next((u for u in db.get_unidades() if u['id'] == uid), None)
    if not alvo:
        return _err('Unidade não encontrada.', 404)
    n = db.count_appointments_unidade(alvo['nome'])
    if n > 0:
        return _err(f"Não dá para remover: a unidade '{alvo['nome']}' tem {n} dia(s) com dados lançados.", 409)
    db.delete_unidade(uid)
    return jsonify({'ok': True})
# ── Conexoes (Configuracao) ──────────────────────────────────────────────────
@app.route('/configuracao/conexoes')
@admin_required
def conexoes_page():
    return render_template('conexoes.html')

@app.route('/api/conexoes/status', methods=['GET'])
@admin_required
def api_conexoes_status():
    """Diz o que esta configurado, SEM devolver chave nem segredo.
    Da URL do webhook so mostramos host e caminho, nunca query string."""
    url = os.environ.get('WEBHOOK_URL', '').strip()
    visivel = ''
    if url:
        try:
            from urllib.parse import urlsplit
            p = urlsplit(url)
            visivel = (p.scheme + '://' + p.netloc + p.path) if p.netloc else '(definida)'
        except Exception:
            visivel = '(definida)'
    try:
        debounce = int(os.environ.get('WEBHOOK_DEBOUNCE', '30'))
    except ValueError:
        debounce = 30
    return jsonify({
        'api_key':          bool(os.environ.get('EXTERNAL_API_KEY', '').strip()),
        'webhook_url':      visivel,
        'webhook_secret':   bool(os.environ.get('WEBHOOK_SECRET', '').strip()),
        'webhook_debounce': debounce,
    })
# ── Bairros das unidades (Configuração) ──────────────────────────────────────
@app.route('/api/bairros', methods=['GET'])
@login_required
def api_list_bairros():
    unidade = request.args.get('unidade')
    if unidade:
        unidade = unquote(unidade)
        if not _valid_unit(unidade):
            return _err(f'Unidade inválida: {unidade}')
    return jsonify(db.get_bairros(unidade))
@app.route('/api/bairros/mapa', methods=['GET'])
@login_required
def api_bairros_mapa():
    """{'PARÁ': ['Augusto', ...], ...} — usado pelo Comparecimento e pelas Metas."""
    return jsonify(db.get_bairros_por_unidade())
@app.route('/api/bairros', methods=['POST'])
@admin_required
def api_create_bairro():
    data = request.get_json(silent=True) or {}
    unidade = (data.get('unidade') or '').strip()
    if not _valid_unit(unidade):
        return _err(f'Unidade inválida: {unidade}')
    try:
        return jsonify(db.create_bairro(unidade, data.get('nome'))), 201
    except ValueError as e:
        return _err(str(e))
@app.route('/api/bairros/<int:bid>', methods=['DELETE'])
@admin_required
def api_delete_bairro(bid):
    db.delete_bairro(bid)
    return jsonify({'ok': True})
# ── Acompanhamento Unidades ──────────────────────────────────────────────────
# ── Faltas e Advertencias ────────────────────────────────────────────────────
@app.route('/faltas')
@login_required
def faltas_page():
    return render_template('faltas.html')


@app.route('/api/flags', methods=['GET'])
@login_required
def api_flags():
    return jsonify(db.get_flags())


@app.route('/api/flags', methods=['POST'])
@login_required
def api_cria_flag():
    d = request.get_json(silent=True) or {}
    try:
        return jsonify(db.create_flag(d.get('nome'), d.get('bg'), d.get('fg'),
                                      d.get('icone', ''), d.get('tipo', ''))), 201
    except ValueError as e:
        return _err(str(e))


@app.route('/api/flags/<int:fid>', methods=['POST'])
@login_required
def api_edita_flag(fid):
    d = request.get_json(silent=True) or {}
    try:
        return jsonify(db.update_flag(fid, d))
    except ValueError as e:
        return _err(str(e))


@app.route('/api/flags/<int:fid>', methods=['DELETE'])
@login_required
def api_apaga_flag(fid):
    usados = db.count_ocorrencias_flag(fid)
    db.delete_flag(fid)
    return jsonify({'ok': True, 'registros_afetados': usados})


@app.route('/api/ocorrencias', methods=['GET'])
@login_required
def api_ocorrencias():
    try:
        ano = int(request.args.get('ano'))
        mes = int(request.args.get('mes'))
    except (TypeError, ValueError):
        return _err('Informe "ano" e "mes".')
    if not (1 <= mes <= 12) or not (1900 <= ano <= 2999):
        return _err('Ano ou mes invalido.')
    dia = request.args.get('dia')
    d = None
    if dia:
        try:
            d = int(dia)
            if not (1 <= d <= 31):
                raise ValueError
        except (TypeError, ValueError):
            return _err('Dia invalido.')
    return jsonify(db.get_ocorrencias(ano, mes, d))


@app.route('/api/ocorrencias_meses', methods=['GET'])
@login_required
def api_ocorrencias_meses():
    """Quais meses do ano tem registro. So leitura, para pintar o seletor."""
    try:
        ano = int(request.args.get('ano'))
    except (TypeError, ValueError):
        return _err('Informe "ano".')
    if not (1900 <= ano <= 2999):
        return _err('Ano invalido.')
    return jsonify(db.meses_com_ocorrencias(ano))


@app.route('/api/ocorrencias', methods=['POST'])
@login_required
def api_salva_ocorrencia():
    d = request.get_json(silent=True) or {}
    try:
        return jsonify(db.upsert_ocorrencia(d))
    except ValueError as e:
        return _err(str(e))


@app.route('/api/ocorrencias/<int:oid>', methods=['DELETE'])
@login_required
def api_apaga_ocorrencia(oid):
    db.delete_ocorrencia(oid)
    return jsonify({'ok': True})

@app.route('/acompanhamento-tmk')
@login_required
def acompanhamento_tmk_page():
    return render_template('acompanhamento_tmk.html')


@app.route('/api/acompanhamento_tmk', methods=['GET'])
@login_required
def api_acomp_tmk():
    """Desempenho individual no periodo, por pessoa e por unidade.

    Tudo sai do que ja existe: o Hora a Hora da cada unidade (agendamentos),
    o Comparecimento (comparecimentos, vendas e punicoes) e as unidades
    reservadas LEADS:: (leads por TMK). Nada de tabela nova.

    Parametros: ano, mes e, opcionalmente, dia (1..31).
    """
    try:
        ano = int(request.args.get('ano'))
        mes = int(request.args.get('mes'))
    except (TypeError, ValueError):
        return _err('Informe "ano" e "mes".')
    if not (1 <= mes <= 12) or not (1900 <= ano <= 2999):
        return _err('Ano ou mes invalido.')

    alvo = None
    dia = request.args.get('dia')
    if dia:
        try:
            d = int(dia)
            if not (1 <= d <= 31):
                raise ValueError
            alvo = '%04d-%02d-%02d' % (ano, mes, d)
        except (TypeError, ValueError):
            return _err('Dia invalido.')

    validas = set(_units())
    lead_keys = _lead_keys()
    pessoas = {}

    def pega(nome):
        p = pessoas.get(nome)
        if p is None:
            p = {'leads': 0, 'unidades': {}}
            pessoas[nome] = p
        return p

    def celula(p, unidade, data):
        u = p['unidades'].get(unidade)
        if u is None:
            u = {'leads': 0, 'ag': 0, 'comp': 0, 'vendas': 0, 'pun': 0, 'dias': {}}
            p['unidades'][unidade] = u
        d = u['dias'].get(data)
        if d is None:
            d = {'ag': 0, 'comp': 0, 'vendas': 0, 'pun': 0}
            u['dias'][data] = d
        return u, d

    def inteiro(v):
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            return 0

    for a in (db.get_appointments_by_month(ano, mes) or []):
        data = a.get('date') or ''
        if alvo and data != alvo:
            continue
        unit = a.get('unit') or ''

        # ── leads por TMK: moram nas unidades reservadas LEADS:: ──
        if unit.startswith(LEADS_PREFIX):
            real = unit[len(LEADS_PREFIX):]
            for r in (a.get('rows') or []):
                if not isinstance(r, dict):
                    continue
                nome = (r.get('name') or '').strip()
                if not nome:
                    continue
                ld = r.get('lead') or {}
                n = sum(inteiro(ld.get(k)) for k in lead_keys)
                if not n:
                    continue
                p = pega(nome)
                p['leads'] += n
                if real in validas:
                    u, _d = celula(p, real, data)
                    u['leads'] += n
            continue

        if unit not in validas:
            continue

        # ── Hora a Hora: agendamentos ──
        for r in (a.get('rows') or []):
            if not isinstance(r, dict):
                continue
            nome = (r.get('name') or '').strip()
            if not nome:
                continue
            slots = r.get('slots') or {}
            tot = sum(inteiro(slots.get(s['key'])) for s in TIME_SLOTS)
            tot += inteiro(r.get('inclusao'))
            if not tot:
                continue
            u, d = celula(pega(nome), unit, data)
            u['ag'] += tot
            d['ag'] += tot

        # ── Comparecimento, vendas e punicoes ──
        cd = a.get('comparecimento_data') or {}
        if not isinstance(cd, dict):
            continue
        for nome, v in cd.items():
            if not isinstance(nome, str):
                continue
            if nome.startswith('__') and nome.endswith('__'):
                continue
            nm = nome.strip()
            n = inteiro(v)
            if not nm or not n:
                continue
            u, d = celula(pega(nm), unit, data)
            u['comp'] += n
            d['comp'] += n
        for chave, mapa in (('vendas', cd.get('__vendas__')),
                            ('pun', cd.get('__punicoes__'))):
            if not isinstance(mapa, dict):
                continue
            for nome, v in mapa.items():
                nm = (nome or '').strip()
                n = inteiro(v)
                if not nm or not n:
                    continue
                u, d = celula(pega(nm), unit, data)
                u[chave] += n
                d[chave] += n

    # quem e lider vem do cadastro de Funcionarios
    lideres = set()
    try:
        for e in (db.get_employees() or []):
            if (e.get('funcao') or '') == 'LIDER':
                lideres.add((e.get('name') or '').strip().upper())
    except Exception:
        pass

    saida = []
    for nome, p in pessoas.items():
        unidades = []
        dias_trab = set()
        tot = {'ag': 0, 'comp': 0, 'vendas': 0, 'pun': 0}
        for un, u in p['unidades'].items():
            dias = []
            for data in sorted(u['dias'].keys()):
                d = u['dias'][data]
                if d['ag'] or d['comp'] or d['vendas'] or d['pun']:
                    dias.append({'data': data, 'ag': d['ag'], 'comp': d['comp'],
                                 'vendas': d['vendas'], 'pun': d['pun']})
                if d['ag']:
                    dias_trab.add(data)          # dia trabalhado = dia com agendamento
            unidades.append({'unidade': un, 'leads': u['leads'], 'ag': u['ag'],
                             'comp': u['comp'], 'vendas': u['vendas'],
                             'pun': u['pun'], 'dias': dias})
            for k in tot:
                tot[k] += u[k]
        if not (tot['ag'] or tot['comp'] or tot['vendas'] or tot['pun'] or p['leads']):
            continue
        unidades.sort(key=lambda x: -x['ag'])
        saida.append({
            'nome': nome,
            'lider': nome.strip().upper() in lideres,
            'dias': len(dias_trab),
            'leads': p['leads'],
            'ag': tot['ag'], 'comp': tot['comp'],
            'vendas': tot['vendas'], 'pun': tot['pun'],
            'adv': [], 'fal': [], 'ates': [],
            'unidades': unidades,
        })
    # ocorrencias da aba Faltas / Advertencias, pelo tipo de cada flag
    try:
        ocor = db.ocorrencias_por_tmk(ano, mes, int(dia) if dia else None)
    except Exception:
        ocor = {}
    for p in saida:
        o = ocor.get(p['nome']) or {}
        p['adv']  = o.get('adv', [])
        p['fal']  = o.get('falta', [])
        p['ates'] = o.get('atestado', [])
    # lideres primeiro; dentro de cada grupo, quem mais agendou
    saida.sort(key=lambda x: (0 if x['lider'] else 1, -x['ag']))
    return jsonify(saida)
# ── Acompanhamento TMK ───────────────────────────────────────────────────────
@app.route('/acompanhamento')
@login_required
def acompanhamento_page():
    return render_template('acompanhamento.html')
@app.route('/api/acompanhamento/<date>', methods=['GET'])
@login_required
def api_get_acomp(date):
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    appt = db.get_appointment(ACOMP_UNIT, date)
    return jsonify(appt or {})
@app.route('/api/acompanhamento/<date>', methods=['POST'])
@login_required
def api_save_acomp(date):
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    data = request.get_json(silent=True) or {}
    rows = data.get('rows', [])
    if not isinstance(rows, list):
        return _err('Campo "rows" deve ser lista.')
    db.upsert_appointment(ACOMP_UNIT, date, '', rows)
    return jsonify({'ok': True})
@app.route('/api/acompanhamento_mes', methods=['GET'])
@login_required
def api_acomp_mes():
    """Todos os dias do mês de uma vez — usado no Resumo do Mês da tela."""
    try:
        ano = int(request.args.get('ano'))
        mes = int(request.args.get('mes'))
    except (TypeError, ValueError):
        return _err('Informe ano e mes válidos.')
    out = [{'date': a['date'], 'rows': a['rows']}
           for a in db.get_appointments_by_month(ano, mes) if a['unit'] == ACOMP_UNIT]
    return jsonify(out)

@app.route('/api/meses_com_dados', methods=['GET'])
@login_required
def api_meses_com_dados():
    """Meses do ano que ja tem lancamento no Acompanhamento Unidades."""
    try:
        ano = int(request.args.get('ano'))
    except (TypeError, ValueError):
        return _err('Informe um ano válido.')
    if not (1900 <= ano <= 2999):
        return _err('Ano fora do intervalo.')
    return jsonify(db.meses_com_dados(ano, ACOMP_UNIT))


@app.route('/api/meses_com_agendamentos', methods=['GET'])
@login_required
def api_meses_com_agendamentos():
    """Meses do ano em que a unidade tem lancamento no Hora a Hora."""
    unit = request.args.get('unit')
    if unit:
        unit = unquote(unit)
    if not _valid_unit(unit):
        return _err(f'Unidade inválida: {unit}')
    try:
        ano = int(request.args.get('ano'))
    except (TypeError, ValueError):
        return _err('Informe um ano válido.')
    if not (1900 <= ano <= 2999):
        return _err('Ano fora do intervalo.')
    return jsonify(db.meses_com_agendamentos(ano, unit))
# ── Fechamento do dia ────────────────────────────────────────────────────────
# Guarda o preenchimento na mesma tabela de appointments, com um "unit"
# reservado — mesmo padrao do Acompanhamento e dos Leads Recebidos, entao
# nao precisa de tabela nova nem de migracao.

@app.route('/fechamento')
@login_required
def fechamento_page():
    return render_template('fechamento.html')

@app.route('/api/fechamento/<date>', methods=['GET'])
@login_required
def api_get_fechamento(date):
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    appt = db.get_appointment(FECH_UNIT, date)
    linhas = (appt or {}).get('rows') or []
    return jsonify(linhas[0] if isinstance(linhas, list) and linhas else {})
def _espelha_leads_recebidos(date, dados):
    """O Fechamento vira o historico do Leads Recebidos.

    O dia passa a ser exatamente o que foi preenchido la: uma linha por
    unidade x canal, so os canais com numero. Canal zerado nao vira linha,
    e o que estava no dia antes e substituido — o Fechamento manda.
    """
    linhas, nomes = [], []
    for u in (dados.get('unidades') or []):
        if not isinstance(u, dict):
            continue
        local = (u.get('nome') or '').strip().upper()
        if not local:
            continue
        for c in (u.get('canais') or []):
            if not isinstance(c, dict):
                continue
            try:
                leads = int(float(c.get('leads') or 0))
                ags   = int(float(c.get('ags') or 0))
            except (TypeError, ValueError):
                continue
            if leads <= 0 and ags <= 0:
                continue
            linhas.append({'local':   local,
                           'agencia': (c.get('rot') or '').strip().upper(),
                           'leads':   leads,
                           'ag':      ags})
            if local not in nomes:
                nomes.append(local)

    db.upsert_appointment(LEADSAG_UNIT, date, '', linhas)

    # O LOCAL precisa existir na lista, senao o seletor da tela nao casa com
    # o valor gravado. Criar e idempotente: se ja existe, da ValueError e segue.
    for nome in nomes:
        try:
            db.create_lead_opcao('local', nome)
        except Exception:
            pass
# ── Fechamento -> Acompanhamento Unidades ───────────────────────────────────
# As siglas do Fechamento sao o mesmo numero que a coluna AGENDAM. do
# Acompanhamento espera. O mapa diz para qual linha cada sigla vai; os nomes
# sao resolvidos contra o cadastro na hora de gravar, sem acento e sem
# maiuscula. Assim, renomear uma unidade nao quebra o espelhamento calado.
SIGLA_DESTINO = {
    'JB':    ('PARÁ', 'José Bonifácio'),
    'TL':    ('PARÁ', 'Telegrafo'),
    'CN':    ('PARÁ', 'Cidade Nova'),
    'AM':    ('PARÁ', 'Augusto'),
    'ANA':   ('PARÁ', 'Ananindeua'),
    'MAR':   ('PARÁ', 'Marambaia'),
    'CAST':  ('PARÁ', 'Castanhal'),
    'JUR':   ('PARÁ', 'Jurunas'),
    'MB':    ('PARÁ', 'Marabá'),
    'CAP':   ('PARÁ', 'Capanema'),
    'MAN 1': ('MANAUS', ''),
    'MAN 2': ('MANOA', ''),
    'MAN 3': ('MANAUS CENTRO', ''),
    'MA':    ('SÃO LUIS', ''),
    'FORT':  ('FORTALEZA', ''),
    'RON':   ('RONDONIA', ''),
}


def _sem_acento(txt):
    import unicodedata
    t = unicodedata.normalize('NFKD', str(txt or '')).encode('ascii', 'ignore').decode()
    return ' '.join(t.split()).strip().upper()


def _espelha_acompanhamento(date, dados):
    """Joga as siglas do Fechamento na coluna AGENDAM. do Acompanhamento.

    So toca no campo 'ag' da linha correspondente: EXAMES, PATOL., DUPLIC. e
    o resto ficam como estao. Linha que ainda nao existe no dia e criada
    zerada. Sigla em branco ou zerada NAO escreve nada — o Fechamento salva
    sozinho enquanto a pessoa digita, e sem essa trava abrir a tela num dia
    ja preenchido zeraria a coluna inteira.
    """
    siglas = dados.get('siglas')
    if not isinstance(siglas, dict):
        return

    # O destino e o dia AGENDADO PARA, nao o dia do fechamento. Sem data
    # valida nao espelha nada: gravar no dia errado e pior do que nao
    # gravar, porque ninguem percebe o erro.
    data_alvo = str(dados.get('data_alvo') or '').strip()
    if not _valid_date(data_alvo):
        return
    try:
        unidades = db.get_unidades() or []
    except Exception:
        return
    uni_por_chave = {}
    for u in unidades:
        nome = u.get('nome') or ''
        if nome:
            uni_por_chave[_sem_acento(nome)] = nome

    bai_por_unidade = {}
    try:
        for b in (db.get_bairros() or []):
            un = b.get('unidade') or ''
            nm = b.get('nome') or ''
            if un and nm:
                bai_por_unidade.setdefault(_sem_acento(un), {})[_sem_acento(nm)] = nm
    except Exception:
        pass

    alvo = {}
    for sigla, valor in siglas.items():
        destino = SIGLA_DESTINO.get(str(sigla).strip().upper())
        if not destino:
            continue
        try:
            n = int(float(valor or 0))
        except (TypeError, ValueError):
            continue
        if n <= 0:
            continue
        rot_uni, rot_bai = destino
        uni = uni_por_chave.get(_sem_acento(rot_uni))
        if not uni:
            continue
        if rot_bai:
            bai = (bai_por_unidade.get(_sem_acento(rot_uni)) or {}).get(_sem_acento(rot_bai))
            if not bai:
                continue
        else:
            bai = uni
        alvo[(uni, bai)] = alvo.get((uni, bai), 0) + n

    if not alvo:
        return

    atual = db.get_appointment(ACOMP_UNIT, data_alvo) or {}
    linhas = atual.get('rows') or []
    if not isinstance(linhas, list):
        linhas = []

    vistos = set()
    for l in linhas:
        if not isinstance(l, dict):
            continue
        chave = (l.get('unidade') or '', l.get('bairro') or '')
        if chave in alvo:
            l['ag'] = alvo[chave]          # o Fechamento manda
            vistos.add(chave)

    for chave, n in alvo.items():
        if chave in vistos:
            continue
        linhas.append({'unidade': chave[0], 'bairro': chave[1], 'ag': n,
                       'ex': 0, 'pa': 0, 'du': 0, 'ue': 0, 'ca': 0,
                       'ge': 0, 'na': 0})

    db.upsert_appointment(ACOMP_UNIT, data_alvo, '', linhas)

@app.route('/api/fechamento/<date>', methods=['POST'])
@login_required
def api_save_fechamento(date):
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    dados = request.get_json(silent=True)
    if not isinstance(dados, dict):
        return _err('Envie um objeto com os dados do fechamento.')
    db.upsert_appointment(FECH_UNIT, date, '', [dados])
    _espelha_leads_recebidos(date, dados)
    _espelha_acompanhamento(date, dados)
    return jsonify({'ok': True})
# ── Leads Recebidos (por local e agência) ────────────────────────────────────
LEADSAG_UNIT = "LEADSAG::GERAL"
@app.route('/leads-recebidos')
@login_required
def leads_recebidos_page():
    return render_template('leads_recebidos.html')
@app.route('/api/leads_recebidos/<date>', methods=['GET'])
@login_required
def api_get_leadsag(date):
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    appt = db.get_appointment(LEADSAG_UNIT, date)
    return jsonify(appt or {})
@app.route('/api/leads_recebidos/<date>', methods=['POST'])
@login_required
def api_save_leadsag(date):
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    data = request.get_json(silent=True) or {}
    rows = data.get('rows', [])
    if not isinstance(rows, list):
        return _err('Campo "rows" deve ser lista.')
    db.upsert_appointment(LEADSAG_UNIT, date, '', rows)
    return jsonify({'ok': True})
@app.route('/api/leads_recebidos_mes', methods=['GET'])
@login_required
def api_leadsag_mes():
    """Todos os dias do mês de uma vez — usado no Resumo Geral."""
    try:
        ano = int(request.args.get('ano'))
        mes = int(request.args.get('mes'))
    except (TypeError, ValueError):
        return _err('Informe ano e mes válidos.')
    out = [{'date': a['date'], 'rows': a['rows']}
           for a in db.get_appointments_by_month(ano, mes) if a['unit'] == LEADSAG_UNIT]
    return jsonify(out)
# ── Leads HxH (leads recebidos hora a hora) ──────────────────────────────────
LEADSHH_UNIT = "LEADSHH::GERAL"
@app.route('/leads-hxh')
@login_required
def leads_hxh_page():
    return render_template('leads_hxh.html')
@app.route('/api/leads_hxh/<date>', methods=['GET'])
@login_required
def api_get_leadshh(date):
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    appt = db.get_appointment(LEADSHH_UNIT, date)
    return jsonify(appt or {})
@app.route('/api/leads_hxh/<date>', methods=['POST'])
@login_required
def api_save_leadshh(date):
    if not _valid_date(date):
        return _err('Data inválida. Use YYYY-MM-DD.')
    data = request.get_json(silent=True) or {}
    rows = data.get('rows', [])
    if not isinstance(rows, list):
        return _err('Campo "rows" deve ser lista.')
    db.upsert_appointment(LEADSHH_UNIT, date, '', rows)
    return jsonify({'ok': True})
@app.route('/api/leads_hxh_mes', methods=['GET'])
@login_required
def api_leadshh_mes():
    """Todos os dias do mês de uma vez — alimenta os indicadores do topo."""
    try:
        ano = int(request.args.get('ano'))
        mes = int(request.args.get('mes'))
    except (TypeError, ValueError):
        return _err('Informe ano e mes válidos.')
    out = [{'date': a['date'], 'rows': a['rows']}
           for a in db.get_appointments_by_month(ano, mes) if a['unit'] == LEADSHH_UNIT]
    return jsonify(out)
@app.route('/api/lead_opcoes', methods=['GET'])
@login_required
def api_list_lead_opcoes():
    # Sem ?tipo=, devolve o mapa de nomes, como a tela de Leads Recebidos espera.
    # Com ?tipo=, devolve os registros com id — e o que permite remover.
    tipo = (request.args.get('tipo') or '').strip().lower()
    if tipo:
        return jsonify(db.get_lead_opcoes(tipo))
    return jsonify(db.get_lead_opcoes_mapa())
@app.route('/api/lead_opcoes', methods=['POST'])
@admin_required
def api_create_lead_opcao():
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(db.create_lead_opcao(data.get('tipo'), data.get('nome'))), 201
    except ValueError as e:
        return _err(str(e))
@app.route('/api/lead_opcoes/<int:oid>', methods=['DELETE'])
@admin_required
def api_delete_lead_opcao(oid):
    db.delete_lead_opcao(oid)
    return jsonify({'ok': True})
# ── Equipe de Confirmação (Configuração) ─────────────────────────────────────
@app.route('/configuracao/equipe')
@admin_required
def equipe_page():
    return render_template('equipe.html', atendentes=_atendentes(), atendente=None)
@app.route('/api/atendentes', methods=['GET'])
@login_required
def api_list_atendentes():
    return jsonify(db.get_atendentes())
@app.route('/api/atendentes', methods=['POST'])
@admin_required
def api_create_atendente():
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(db.create_atendente(data.get('nome'))), 201
    except ValueError as e:
        return _err(str(e))
@app.route('/api/atendentes/<int:aid>', methods=['DELETE'])
@admin_required
def api_delete_atendente(aid):
    alvo = next((a for a in db.get_atendentes() if a['id'] == aid), None)
    if not alvo:
        return _err('Pessoa não encontrada.', 404)
    n = db.count_confirmacoes_atendente(alvo['nome'])
    if n > 0:
        return _err(f"Não dá para remover: '{alvo['nome']}' tem {n} confirmação(ões) registrada(s).", 409)
    db.delete_atendente(aid)
    return jsonify({'ok': True})
# ── API: Siglas do Fechamento ────────────────────────────────────────────────
@app.route('/api/siglas', methods=['GET'])
@login_required
def api_list_siglas():
    return jsonify(db.get_siglas())
@app.route('/api/siglas', methods=['POST'])
@login_required
def api_create_sigla():
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(db.create_sigla(data.get('nome'))), 201
    except ValueError as e:
        return _err(str(e))
@app.route('/api/siglas/<nome>', methods=['DELETE'])
@admin_required
def api_delete_sigla(nome):
    nome = unquote(nome).strip().upper()
    if not any(g['nome'] == nome for g in db.get_siglas()):
        return _err('Sigla não encontrada.', 404)
    db.delete_sigla(nome)
    return jsonify({'ok': True})
# -- API Externa (relatorios so-leitura, protegida por X-API-Key) --
def _ext_auth_ok():
    key = os.environ.get('EXTERNAL_API_KEY', '')
    return bool(key) and request.headers.get('X-API-Key', '') == key

@app.route('/api/externo/hora-a-hora', methods=['GET'])
@limiter.limit("60 per minute")
def api_ext_hora():
    if not _ext_auth_ok():
        return jsonify({'error': 'unauthorized'}), 401
    unidade = (request.args.get('unidade') or '').strip()
    data = (request.args.get('data') or '').strip()
    if not unidade or not data:
        return jsonify({'error': 'parametros unidade e data (YYYY-MM-DD) obrigatorios'}), 400
    appt = db.get_appointment(unidade, data) or {}
    horas = {}
    for r in (appt.get('rows') or []):
        for k, v in (r.get('slots') or {}).items():
            try:
                horas[k] = horas.get(k, 0) + int(float(v or 0))
            except Exception:
                pass
    total = sum(horas.values())
    meta_dia = 0
    try:
        ano = int(data[0:4]); mes = int(data[5:7])
        for m in (db.get_metas(ano, mes) or []):
            if (m.get('unidade') or '') == unidade and not (m.get('bairro') or ''):
                meta_dia = m.get('meta_dia') or 0
                break
    except Exception:
        pass
    lista = [{'hora': k, 'ags': horas[k]} for k in sorted(horas.keys()) if horas[k] > 0]
    return jsonify({'unidade': unidade, 'data': data, 'horas': lista, 'total': total, 'meta_dia': meta_dia, 'falta': max(0, (meta_dia or 0) - total)})

@app.route('/api/externo/metas', methods=['GET'])
@limiter.limit("60 per minute")
def api_ext_metas_pub():
    if not _ext_auth_ok():
        return jsonify({'error': 'unauthorized'}), 401
    try:
        ano = int(request.args.get('ano')); mes = int(request.args.get('mes'))
    except Exception:
        return jsonify({'error': 'parametros ano e mes obrigatorios'}), 400
    metas = db.get_metas(ano, mes) or []
    real_unit = {}
    real_bairro = {}
    for appt in (db.get_appointments_by_month(ano, mes) or []):
        u = appt.get('unit') or ''
        cd = appt.get('comparecimento_data') or {}
        for nm, v in cd.items():
            if nm == '__bairros__':
                for b, obj in (v or {}).items():
                    try:
                        real_bairro[(u, b)] = real_bairro.get((u, b), 0) + int((obj or {}).get('comp') or 0)
                    except Exception:
                        pass
                continue
            if nm in ('__punicoes__', '__vendas__'):
                continue
            try:
                real_unit[u] = real_unit.get(u, 0) + int(float(v or 0))
            except Exception:
                pass
    out = []
    for m in metas:
        u = m.get('unidade') or ''
        b = m.get('bairro') or ''
        real = real_bairro.get((u, b), 0) if b else real_unit.get(u, 0)
        meta_mes = m.get('meta_comp') or 0
        out.append({'unidade': u, 'bairro': b, 'meta_mes': meta_mes, 'meta_dia': m.get('meta_dia') or 0, 'meta_hora': m.get('meta_hora') or 0, 'realizado': real, 'pct': round((real / meta_mes) * 100) if meta_mes else 0})
    return jsonify({'ano': ano, 'mes': mes, 'metas': out})

@app.route('/api/externo/confirmacoes', methods=['GET'])
@limiter.limit("60 per minute")
def api_ext_confs():
    if not _ext_auth_ok():
        return jsonify({'error': 'unauthorized'}), 401
    data_str = (request.args.get('data') or '').strip()
    atendente = (request.args.get('atendente') or '').strip() or None
    if not data_str:
        return jsonify({'error': 'parametro data (DD/MM/YYYY) obrigatorio'}), 400
    confs = db.get_confirmacoes(data_str=data_str, atendente=atendente) or []
    return jsonify({'data': data_str, 'atendente': atendente, 'total': len(confs), 'confirmacoes': confs})
# ── API externa: UMA rota com toda a base (feita para Power BI) ─────────────
# Le o banco uma vez so e devolve os tres conjuntos ja prontos, sem filtro de
# periodo. Quem monta o Power BI escolhe la dentro o recorte que quer ver.
def _ext_num(v):
    try:
        return int(float(v or 0))
    except (TypeError, ValueError):
        return 0

@app.route('/api/externo/dados', methods=['GET'])
@limiter.limit("30 per minute")
def api_ext_dados():
    if not _ext_auth_ok():
        return jsonify({'error': 'unauthorized'}), 401

    regiao_de = {}
    try:
        for u in (db.get_unidades() or []):
            regiao_de[u.get('nome') or ''] = u.get('regiao') or ''
    except Exception:
        pass
    unidades_validas = set(_units())

    acomp, leads, hora = [], [], []

    for a in (db.get_appointments_all() or []):
        unit = a.get('unit') or ''
        data = a.get('date')

        # ── Acompanhamento: uma linha por dia x unidade x bairro ──
        if unit == ACOMP_UNIT:
            for l in (a.get('rows') or []):
                if not isinstance(l, dict):
                    continue
                unidade = l.get('unidade') or ''
                ag = _ext_num(l.get('ag'))
                ex = _ext_num(l.get('ex'))
                acomp.append({
                    'data': data,
                    'regiao': regiao_de.get(unidade, ''),
                    'unidade': unidade,
                    'bairro': l.get('bairro') or '',
                    'agendamentos': ag,
                    'exames': ex,
                    'patologias': _ext_num(l.get('pa')),
                    'conversao': round(ex / ag * 100) if ag else 0,
                    'duplicado': _ext_num(l.get('du')),
                    'unidade_errada': _ext_num(l.get('ue')),
                    'cancelamento_dia_anterior': _ext_num(l.get('ca')),
                    'gestante_lactante': _ext_num(l.get('ge')),
                    'nao_agendado': _ext_num(l.get('na')),
                })
            continue

        # ── Leads recebidos: uma linha por dia x local x agencia ──
        if unit == LEADSAG_UNIT:
            for l in (a.get('rows') or []):
                if not isinstance(l, dict):
                    continue
                leads.append({
                    'data': data,
                    'local': l.get('local') or '',
                    'agencia': l.get('agencia') or '',
                    'leads': _ext_num(l.get('leads')),
                    'agendamentos': _ext_num(l.get('ag')),
                })
            continue

        # ── Hora a Hora: uma linha por dia x unidade x atendente ──
        if unit in unidades_validas:
            cd   = a.get('comparecimento_data') or {}
            puns = cd.get('__punicoes__') or {}
            vnds = cd.get('__vendas__') or {}
            for r in (a.get('rows') or []):
                if not isinstance(r, dict):
                    continue
                nome = (r.get('name') or '').strip()
                if not nome:
                    continue
                slots = r.get('slots') or {}
                total = sum(_ext_num(slots.get(s['key'])) for s in TIME_SLOTS) + _ext_num(r.get('inclusao'))
                hora.append({
                    'data': data,
                    'unidade': unit,
                    'lider': (r.get('leader') or a.get('leader') or ''),
                    'nome': nome,
                    'agendamentos': total,
                    'comparecimentos': _ext_num(cd.get(nome)),
                    'punicoes': _ext_num(puns.get(nome)),
                    'vendas': _ext_num(vnds.get(nome)),
                })

    return jsonify({
        'gerado_em': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'acompanhamento': acomp,
        'leads': leads,
        'hora_a_hora': hora,
    })
@app.route('/api/users/<int:uid>/role', methods=['POST'])
@admin_required
def api_set_user_role(uid):
    data = request.get_json(silent=True) or {}
    try:
        db.set_user_role(uid, data.get('role', 'all'))
        return jsonify({'ok': True})
    except ValueError as e:
        return _err(str(e))
# ── Troca CRM (pedidos vindos da extensao do RD Station) ─────────────────────
# O atendente pede a troca de responsavel pela extensao; o pedido cai aqui e a
# lider resolve. Cada lider cadastra o token DELA do RD: com token, o "Aprovar"
# troca no RD em nome dela; sem token, so marca como feito e a troca e na mao.
import urllib.error
from datetime import timedelta
from urllib.parse import quote

RD_DEAL_URL = 'https://crm.rdstation.com/api/v1/deals/'

def _extn_auth_ok():
    """Chave propria da extensao.

    NAO e a EXTERNAL_API_KEY: aquela da leitura dos relatorios, e esta aqui
    vai no navegador de cada operador. Se vazar, o pior que acontece e alguem
    encher a fila de pedido falso — nenhum dado sai.
    """
    key = os.environ.get('EXTN_API_KEY', '').strip()
    return bool(key) and request.headers.get('X-API-Key', '') == key

RD_API = 'https://crm.rdstation.com/api/v1/'

def _rd_get(caminho, token):
    """GET simples na API do RD. Devolve (status, texto). Nunca levanta erro."""
    url = (RD_API + caminho + ('&' if '?' in caminho else '?')
           + 'token=' + quote(token, safe=''))
    try:
        with urllib.request.urlopen(urllib.request.Request(url), timeout=12) as r:
            return r.status, r.read(2000).decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(300).decode('utf-8', 'replace')
        except Exception:
            return e.code, ''
    except Exception as e:
        return 0, str(e)

def _rd_dono_de(d):
    """Acha nome/e-mail/empresa na resposta do RD, mesmo se vier aninhada.

    A doc diz que vem no primeiro nivel, mas conta diferente pode devolver
    dentro de "user" ou "data". Procurar nos tres custa nada e evita dizer
    "nao sei de quem e" quando o dado estava ali.
    """
    if not isinstance(d, dict):
        return {}
    for n in (d, d.get('user'), d.get('data'), d.get('token')):
        if isinstance(n, dict) and (n.get('name') or n.get('email')):
            return {'nome':  str(n.get('name') or '').strip(),
                    'email': str(n.get('email') or '').strip(),
                    'org':   str(n.get('organization') or n.get('account') or '').strip()}
    return {}

def _rd_testa_token(token):
    """Confere o token contra o RD ANTES de guardar.

    Devolve (ok, motivo, dono). Em 'dono' vem quem e o dono do token no RD.
    Quando o nome nao vem, 'dono' traz um '_diag' dizendo POR QUE nao veio —
    sem isso a tela so sabe dizer "nao sei", e ninguem consegue consertar.
    """
    def _limpo(txt):
        # o corpo da resposta nunca deve ecoar o token de volta para a tela
        return str(txt or '').replace(token, '***')[:140]

    st, corpo = _rd_get('token/check', token)
    if 200 <= st < 300:
        try:
            d = _json.loads(corpo or '{}')
        except Exception:
            d = {}
        dono = _rd_dono_de(d)
        if dono.get('nome') or dono.get('email'):
            return True, '', dono
        return True, '', {'_diag': 'o RD respondeu 200 sem nome: ' + _limpo(corpo)}
    if st in (401, 403):
        return False, 'O RD recusou esse token (%s). Confira se copiou inteiro.' % st, {}
    if st == 0:
        return False, 'Nao consegui falar com o RD: %s' % _limpo(corpo), {}
    # O endpoint de conferencia pode nao existir nessa conta: cai no /users,
    # que e o mesmo que a extensao usa. Por esse caminho nao da para saber
    # o nome do dono — a tela diz isso, e diz o motivo.
    diag = 'o /token/check respondeu %s' % st
    st2, corpo2 = _rd_get('users', token)
    if 200 <= st2 < 300:
        return True, '', {'_diag': diag}
    if st2 in (401, 403):
        return False, 'O RD recusou esse token (%s). Confira se copiou inteiro.' % st2, {}
    return False, 'O RD respondeu %s ao conferir o token.' % st2, {}

def _rd_troca_responsavel(deal_id, user_id, token):
    """Troca o responsavel da negociacao no RD, com o token de quem aprovou.

    O user_id e o do RD, do jeito que a extensao mandou — aqui nao ha de-para.
    Como o token e pessoal, o RD registra a LIDER como autora da troca e
    aplica as permissoes dela.

    Nunca levanta erro: o que der errado vira texto, aparece na tela e fica
    gravado no pedido. Clicar e nao saber o que aconteceu e pior que o erro.
    """
    if not str(token or '').strip():
        return False, 'Voce ainda nao cadastrou seu token do RD.'
    if not str(deal_id or '').strip():
        return False, 'Pedido sem o ID da negociacao.'
    if not str(user_id or '').strip():
        return False, 'Pedido sem o ID do usuario no RD.'
    url = (RD_API + 'deals/' + quote(str(deal_id).strip(), safe='')
           + '?token=' + quote(str(token).strip(), safe=''))
    corpo = _json.dumps({'deal': {'user_id': str(user_id).strip()}}).encode('utf-8')
    req = urllib.request.Request(url, data=corpo, method='PUT',
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            if 200 <= r.status < 300:
                return True, ''
            return False, 'RD respondeu %s.' % r.status
    except urllib.error.HTTPError as e:
        try:
            detalhe = e.read().decode('utf-8', 'replace')[:300]
        except Exception:
            detalhe = ''
        if e.code in (401, 403):
            return False, ('Seu token nao tem permissao para esta negociacao '
                           '(%s). %s' % (e.code, detalhe)).strip()
        return False, ('RD respondeu %s. %s' % (e.code, detalhe)).strip()
    except Exception as e:
        return False, 'Nao consegui falar com o RD: %s' % e

# ── Token pessoal de cada lider ──────────────────────────────────────────────
# Cada uma cadastra o SEU token do RD. O valor nunca volta para a tela, nem
# para a dona: a rota de leitura devolve so "configurado sim/nao" e as datas.
@app.route('/api/meu_rd_token', methods=['GET'])
@login_required
def api_meu_rd_token():
    dados = db.status_crm_token(session.get('user_id'))
    dados['cifra_ligada'] = db.cifra_ligada()
    return jsonify(dados)

@app.route('/api/meu_rd_token', methods=['POST'])
@limiter.limit("10 per minute")
@login_required
def api_salva_meu_rd_token():
    """Duas fases.

    Sem "confirmar", so pergunta ao RD de quem e o token e devolve o nome —
    nada e gravado. Com "confirmar", grava.

    E a lider quem diz "esse nome sou eu": o sistema nao tem como saber
    sozinho se o token que ela colou e o dela ou o de outra pessoa.
    """
    if not db.cifra_ligada():
        return _err('Servidor sem chave de cifra: defina FLASK_SECRET ou '
                    'TOKEN_KEY. Credencial em claro no banco, nao.', 503)
    dados = request.get_json(silent=True) or {}
    token = str(dados.get('token') or '').strip()
    if len(token) < 10:
        return _err('Cole o token inteiro.')
    ok, motivo, dono = _rd_testa_token(token)
    if not ok:
        return _err(motivo)
    if not dados.get('confirmar'):
        return jsonify({'confirmar': True, 'dono': dono})
    uid = session.get('user_id')
    if not db.set_crm_token(uid, token, dono.get('nome', ''),
                            dono.get('email', ''), dono.get('org', '')):
        return _err('Nao consegui guardar o token.', 500)
    return jsonify(db.status_crm_token(uid))

@app.route('/api/meu_rd_token', methods=['DELETE'])
@login_required
def api_apaga_meu_rd_token():
    db.delete_crm_token(session.get('user_id'))
    return jsonify({'ok': True})

@app.route('/troca-crm')
@login_required
def troca_crm_page():
    return render_template('troca_crm.html')

@app.route('/api/crm_trocas', methods=['GET'])
@login_required
def api_crm_trocas():
    status  = (request.args.get('status') or '').strip().lower()
    unidade = (request.args.get('unidade') or '').strip()
    desde = None
    try:
        dias = int(request.args.get('dias') or 0)
        if dias > 0:
            desde = (datetime.utcnow() - timedelta(days=min(dias, 365))).isoformat()
    except (TypeError, ValueError):
        desde = None
    if status not in ('pendente', 'feito', 'recusado', 'erro'):
        status = None
    meu = db.status_crm_token(session.get('user_id'))
    return jsonify({
        # "ligado" agora e por pessoa: quem tem token aprova de verdade.
        'rd_ligado':    bool(meu.get('configurado')) and db.cifra_ligada(),
        'cifra_ligada': db.cifra_ligada(),
        'meu_token':    meu,
        'unidades':     db.get_crm_unidades(),
        'pendentes':    db.count_crm_pendentes(),
        'itens':        db.get_crm_trocas(status=status,
                                          unidade=unidade or None,
                                          desde=desde),
    })

@app.route('/api/crm_trocas/pendentes', methods=['GET'])
@login_required
def api_crm_pendentes():
    """So o numero, para o contador da barra lateral."""
    return jsonify({'n': db.count_crm_pendentes()})

@app.route('/api/crm_trocas/<int:tid>/aprovar', methods=['POST'])
@login_required
def api_crm_aprovar(tid):
    t = db.get_crm_troca(tid)
    if not t:
        return _err('Pedido não encontrado.', 404)
    if t['status'] == 'feito':
        return jsonify(t)
    quem  = session.get('username') or ''
    uid   = session.get('user_id')
    token = db.get_crm_token(uid) if uid else None
    if not token:
        # Sem token pessoal o Connecting nao fala com o RD: so registra que
        # foi resolvido, e a troca continua sendo na mao.
        return jsonify(db.resolve_crm_troca(tid, 'feito', quem))
    ok, motivo = _rd_troca_responsavel(t['deal_id'], t['resp_novo_id'], token)
    if ok:
        db.marca_uso_crm_token(uid)
        return jsonify(db.resolve_crm_troca(tid, 'feito', quem))
    return jsonify(db.resolve_crm_troca(tid, 'erro', quem, motivo))
@app.route('/api/crm_trocas/<int:tid>/recusar', methods=['POST'])
@login_required
def api_crm_recusar(tid):
    t = db.resolve_crm_troca(tid, 'recusado', session.get('username') or '')
    if not t:
        return _err('Pedido não encontrado.', 404)
    return jsonify(t)

@app.route('/api/externo/troca-crm', methods=['POST'])
@limiter.limit("120 per minute")
def api_ext_troca_crm():
    """A extensao chama aqui, do service worker, com a X-API-Key da EXTN_API_KEY."""
    if not _extn_auth_ok():
        return jsonify({'error': 'unauthorized'}), 401
    dados = request.get_json(silent=True) or {}
    if not str(dados.get('deal_id') or '').strip():
        return jsonify({'error': 'deal_id obrigatorio'}), 400
    if not str(dados.get('solicitante') or '').strip():
        return jsonify({'error': 'solicitante obrigatorio'}), 400
    novo, duplicado = db.create_crm_troca(dados)
    if not novo:
        return jsonify({'error': 'nao consegui gravar o pedido'}), 500
    if duplicado:
        # Nao e erro: o pedido dele ja estava na fila. A extensao trata 409
        # como aviso, nao como falha.
        return jsonify({'ok': True, 'id': novo['id'], 'duplicado': True}), 409
    return jsonify({'ok': True, 'id': novo['id']}), 201
# ── Bootstrap ─────────────────────────────────────────────────────────────────
# Inicializa o banco assim que o módulo é importado (necessário pro Gunicorn
# em produção). Em dev, o `python app.py` também passa por aqui antes do run.
db.init_db()
if __name__ == '__main__':
    debug = os.getenv('FLASK_DEBUG', '0') == '1'
    port = int(os.getenv('PORT', '5000'))
    print(f"\nSistema de Agendamentos rodando em http://localhost:{port}")
    print(f"  debug={debug}\n")
    app.run(debug=debug, port=port)
