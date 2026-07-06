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
# ── Rate Limiting & Cache ─────────────────────────────────────────────────────
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})
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
UNITS = ["PARÁ", "MANAUS", "MANOA", "SÃO LUIZ", "FORTALEZA", "AÇÃO"]
# Prefixo de "unidade" reservada para Leads Recebidos (uma por unidade real).
# Reusa a tabela appointments (rows é JSON), então não precisa de migração.
# Ex.: os leads de PARÁ ficam armazenados sob a unit "LEADS::PARÁ".
LEADS_PREFIX = "LEADS::"
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
    return isinstance(u, str) and u in UNITS
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
        uid = db.create_user(data.get('username'), data.get('password'))
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
    if not name:
        return _err('Campo "name" é obrigatório')
    if not _valid_unit(unit):
        return _err(f'Campo "unit" inválido. Use um de: {UNITS}')
    eid = db.create_employee(name, unit, active)
    return jsonify({'id': eid, 'name': name, 'unit': unit, 'active': active}), 201
@app.route('/api/employees/<int:eid>', methods=['DELETE'])
@login_required
def api_delete_employee(eid):
    hard = request.args.get('hard') == 'true'
    if hard:
        db.delete_employee_hard(eid)
    else:
        db.deactivate_employee(eid)
    return jsonify({'ok': True, 'hard': hard})
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
    # Nunca expõe as "unidades" reservadas de Leads nos agendamentos nem no dashboard
    appts = [a for a in appts if not a['unit'].startswith(LEADS_PREFIX)]
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
@app.route('/api/constants')
@login_required
@cache.cached(timeout=3600)
def api_constants():
    return jsonify({'units': UNITS, 'months': MONTHS, 'time_slots': TIME_SLOTS})
# Chaves de leads que entraram (espelham as definidas em leads.html)
LEAD_KEYS = ['wbp_lead', 'vbot_lead', 'antigos_lead', 'mkt_lead', 'whats_lead', 'mabe_lead']
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
    # Soma os leads só das "unidades" reservadas LEADS::, por unidade real
    totais = {u: 0 for u in UNITS}
    for a in appts:
        unit = a['unit']
        if not unit.startswith(LEADS_PREFIX):
            continue
        unidade_real = unit[len(LEADS_PREFIX):]
        if unidade_real not in totais:
            continue
        for r in (a.get('rows') or []):
            lead_data = r.get('lead') or {}
            totais[unidade_real] += sum(int(lead_data.get(k) or 0) for k in LEAD_KEYS)
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
    for a in appts:
        unit = a['unit']
        if not unit.startswith(LEADS_PREFIX):
            continue
        for r in (a.get('rows') or []):
            nome = (r.get('name') or '').strip()
            if not nome:
                continue
            lead_data = r.get('lead') or {}
            total = sum(int(lead_data.get(k) or 0) for k in LEAD_KEYS)
            por_tmk[nome] = por_tmk.get(nome, 0) + total
    return jsonify(por_tmk)
def _role_allowed(*roles):
    user_role = session.get('role', 'all')
    return user_role == 'all' or user_role == 'admin' or user_role in roles
ATENDENTES = ['VIVIANE', 'DIELLEM', 'LIDIENE', 'KEILANE', 'LUANE', 'MARIA']
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
    return v if v in ATENDENTES else None
@app.route('/confirmacao')
@login_required
def confirmacao_analise():
    if not _role_allowed('confirmacao'):
        return redirect(url_for('dashboard'))
    return render_template('analise_confirmacao.html',
                           atendentes=ATENDENTES,
                           unidades_conf=UNIDADES_CONF,
                           atendente=None)
@app.route('/confirmacao/<atendente>')
@login_required
def confirmacao_page(atendente=None):
    if not _role_allowed('confirmacao'):
        return redirect(url_for('dashboard'))
    if atendente:
        atendente = atendente.upper()
        if atendente not in ATENDENTES:
            return redirect(url_for('confirmacao_analise'))
    return render_template('confirmacao.html', atendente=atendente, atendentes=ATENDENTES)
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
@app.route('/api/users/<int:uid>/role', methods=['POST'])
@admin_required
def api_set_user_role(uid):
    data = request.get_json(silent=True) or {}
    try:
        db.set_user_role(uid, data.get('role', 'all'))
        return jsonify({'ok': True})
    except ValueError as e:
        return _err(str(e))
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
