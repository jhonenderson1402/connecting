"""
Camada de banco de dados do sistema Connecting.
Usa SQLAlchemy como ORM/Core, o que permite o MESMO codigo rodar em:
  - SQLite (desenvolvimento local — sem configurar nada, gera agendamentos.db)
  - PostgreSQL (producao — basta definir DATABASE_URL no ambiente)
A escolha do banco e feita pela variavel de ambiente DATABASE_URL.
Exemplo de URL PostgreSQL: postgresql+psycopg2://user:pass@host:5432/dbname
A API publica (funcoes que app.py chama) NAO mudou: get_employees,
create_employee, verify_password, etc. continuam com a mesma assinatura.
"""
import os
import re
import json
from datetime import datetime
from sqlalchemy import Float
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, UniqueConstraint, Index,
    select, insert, update, delete, func, and_, text,
)
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
# ---- Conexao ----------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(__file__), 'agendamentos.db')
DEFAULT_SQLITE_URL = f"sqlite:///{DB_PATH}"
# Em producao: definir DATABASE_URL apontando pro PostgreSQL.
# Em dev: sem variavel, usa SQLite local automaticamente.
DATABASE_URL = os.environ.get('DATABASE_URL', DEFAULT_SQLITE_URL)
# Railway/Heroku as vezes usam 'postgres://' (legado); SQLAlchemy 2.x exige 'postgresql://'
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
# Seleciona o driver correto por ambiente:
# - Vercel (serverless): pg8000 (Python puro, sem dependencias nativas)
# - Railway/local: psycopg2 (nativo, mais rapido)
is_serverless = os.environ.get('VERCEL') or os.environ.get('VERCEL_ENV')
if 'postgresql' in DATABASE_URL:
    # Remove driver existente para normalizar
    DATABASE_URL = re.sub(r'postgresql\+\w+://', 'postgresql://', DATABASE_URL)
    if is_serverless:
        DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+pg8000://')
    else:
        DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg2://')
_engine_kwargs = {}
if DATABASE_URL.startswith('sqlite'):
    _engine_kwargs['connect_args'] = {'check_same_thread': False}
engine = create_engine(DATABASE_URL, **_engine_kwargs, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)
Base = declarative_base()
DEFAULT_ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
# Senha do admin inicial vem do ambiente (ADMIN_PASS).
# Em dev, se não definida, usa um padrão que DEVE ser trocado no 1º login.
# Em produção (DATABASE_URL definido) sem ADMIN_PASS, gera uma senha aleatória forte.
DEFAULT_ADMIN_PASS = os.environ.get('ADMIN_PASS')
# ---- Modelos ----------------------------------------------------------------
class Employee(Base):
    __tablename__ = 'employees'
    id     = Column(Integer, primary_key=True, autoincrement=True)
    name   = Column(String(200), nullable=False)
    unit   = Column(String(100), nullable=False)
    active = Column(Integer, default=1)
    funcao = Column(String(20), default='ATENDENTE')
    __table_args__ = (
        Index('idx_emp_unit_active', 'unit', 'active'),
    )
class Appointment(Base):
    __tablename__ = 'appointments'
    id     = Column(Integer, primary_key=True, autoincrement=True)
    unit   = Column(String(100), nullable=False)
    date   = Column(String(10),  nullable=False)
    leader = Column(String(200), default='')
    rows   = Column(Text, default='[]')
    comparecimento_data = Column(Text, default='{}')
    __table_args__ = (
        UniqueConstraint('unit', 'date', name='uq_unit_date'),
        Index('idx_appt_date', 'date'),
        Index('idx_appt_unit_date', 'unit', 'date'),
    )
class User(Base):
    __tablename__ = 'users'
    id            = Column(Integer, primary_key=True, autoincrement=True)
    username      = Column(String(150), nullable=False, unique=True)
    password_hash = Column(String(300), nullable=False)
    role          = Column(String(50), default='all')  # 'agendamento', 'confirmacao', 'all', 'admin'
    created_at    = Column(String(40),  default=lambda: datetime.utcnow().isoformat())
    __table_args__ = (
        Index('idx_users_username', 'username'),
    )
class Confirmacao(Base):
    __tablename__ = 'confirmacoes'
    id        = Column(Integer, primary_key=True, autoincrement=True)
    atendente = Column(String(200), default='')   # dona da confirmacao (VIVIANE, LUANE, etc.)
    mes       = Column(String(20),  default='')
    data_str  = Column(String(10),  default='')   # DD/MM/YYYY
    cliente   = Column(String(300), default='')
    tmk       = Column(String(200), default='')
    unidade   = Column(String(100), default='')
    horario   = Column(String(20),  default='')
    contato   = Column(String(100), default='')
    flag      = Column(String(100), default='')
    observacao = Column(Text, default='')
    created_at = Column(String(40), default=lambda: datetime.utcnow().isoformat())
    __table_args__ = (
        Index('idx_conf_mes', 'mes'),
        Index('idx_conf_data', 'data_str'),
        Index('idx_conf_atendente', 'atendente'),
    )
class Meta(Base):
    __tablename__ = 'metas'
    id         = Column(Integer, primary_key=True, autoincrement=True)
    ano        = Column(Integer, nullable=False)
    mes        = Column(Integer, nullable=False)          # 1 a 12
    unidade    = Column(String(100), nullable=False)      # PARÁ, MANAUS, etc.
    bairro     = Column(String(120), default='')          # só para a PARÁ; vazio nas demais
    meta_agend = Column(Integer, default=0)
    meta_comp  = Column(Integer, default=0)
    meta_dia   = Column(Float, default=0)
    meta_hora  = Column(Float, default=0)
    meta_conv  = Column(Integer, default=0)               # porcentagem 0-100
    updated_at = Column(String(40), default='')
    __table_args__ = (
        UniqueConstraint('ano', 'mes', 'unidade', 'bairro', name='uq_meta_periodo'),
        Index('idx_meta_mes', 'ano', 'mes'),
    )
# ---- Inicializacao ----------------------------------------------------------
def init_db():
    """Cria tabelas e indices se ainda nao existirem. Idempotente.
    Em ambiente serverless (Vercel), o DDL e pulado para evitar timeout —
    as tabelas devem ser criadas via script separado (veja create_tables.py)."""
    is_serverless = os.environ.get('VERCEL') or os.environ.get('VERCEL_ENV')
    if is_serverless:
        # No Vercel: assume que o banco ja existe.
        # Apenas garante o admin sem rodar CREATE TABLE / ALTER TABLE.
        try:
            ensure_default_admin()
        except Exception as e:
            print("ERRO AO CRIAR ADMIN:", e)
        return
    Base.metadata.create_all(engine)
    _run_migrations()
    ensure_default_admin()
def _run_migrations():
    """Aplica migrações incrementais no banco existente (idempotente)."""
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE metas ADD COLUMN meta_dia DOUBLE PRECISION DEFAULT 0"))
            conn.commit()
            print("[migration] Coluna 'meta_dia' adicionada à tabela metas.")
        except Exception:
            conn.rollback()  # Coluna já existe, ignora
        try:
            conn.execute(text("ALTER TABLE metas ADD COLUMN meta_hora DOUBLE PRECISION DEFAULT 0"))
            conn.commit()
            print("[migration] Coluna 'meta_hora' adicionada à tabela metas.")
        except Exception:
            conn.rollback()  # Coluna já existe, ignora
        # Migração 1: adiciona coluna 'role' na tabela users se não existir
        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT 'all'"))
            conn.commit()
            print("[migration] Coluna 'role' adicionada à tabela users.")
        except Exception:
            conn.rollback()  # Coluna já existe, ignora
        # Migração 2: adiciona coluna 'atendente' na tabela confirmacoes se não existir
        try:
            conn.execute(text("ALTER TABLE confirmacoes ADD COLUMN atendente VARCHAR(200) DEFAULT ''"))
            conn.commit()
            print("[migration] Coluna 'atendente' adicionada à tabela confirmacoes.")
        except Exception:
            conn.rollback()  # Coluna já existe, ignora
        # Migração: adiciona coluna 'funcao' na tabela employees se não existir
        try:
            conn.execute(text("ALTER TABLE employees ADD COLUMN funcao VARCHAR DEFAULT 'ATENDENTE'"))
            conn.commit()
            print("[migration] Coluna 'funcao' adicionada à tabela employees.")
        except Exception:
            conn.rollback()  # Coluna já existe, ignora
        # Migração 3: cria a tabela 'metas' se não existir (Base.metadata.create_all já cobre,
        # mas garantimos aqui para bancos que rodaram create_all antes deste modelo existir).
        # Nada a fazer além do create_all; deixado como marcador.
def ensure_default_admin():
    """Se nao houver nenhum usuario, cria o admin inicial (papel 'admin')."""
    import secrets
    with SessionLocal() as s:
        n = s.scalar(select(func.count(User.id)))
        if n == 0:
            senha = DEFAULT_ADMIN_PASS
            gerada = False
            if not senha:
                if not DATABASE_URL.startswith('sqlite'):
                    senha = secrets.token_urlsafe(12)
                    gerada = True
                else:
                    senha = 'trocar-senha-123'
            s.add(User(
                username=DEFAULT_ADMIN_USER,
                password_hash=generate_password_hash(senha),
                role='admin',
            ))
            s.commit()
            print("\n[!] Nenhum usuario encontrado. Criado admin inicial:")
            print(f"    usuario: {DEFAULT_ADMIN_USER}")
            if gerada:
                print(f"    senha (ALEATORIA, anote agora): {senha}")
            else:
                print(f"    senha: {senha}")
            print(f"    >>> TROQUE essa senha apos o primeiro login! <<<\n")
# ---- Helpers ----------------------------------------------------------------
def _safe_json_loads(s, default):
    try:
        return json.loads(s) if s else default
    except (ValueError, TypeError):
        return default
def _appt_to_dict(a):
    return {
        'id': a.id,
        'unit': a.unit,
        'date': a.date,
        'leader': a.leader or '',
        'rows': _safe_json_loads(a.rows, []),
        'comparecimento_data': _safe_json_loads(a.comparecimento_data, {}),
    }
# ---- Users / Auth -----------------------------------------------------------
def get_user_by_username(username):
    with SessionLocal() as s:
        u = s.scalar(select(User).where(User.username == username))
        if not u:
            return None
        return {'id': u.id, 'username': u.username,
                'password_hash': u.password_hash, 'created_at': u.created_at,
                'role': u.role or 'all'}
def verify_password(username, password):
    user = get_user_by_username(username)
    if not user:
        return None
    if check_password_hash(user['password_hash'], password):
        return {'id': user['id'], 'username': user['username'], 'role': user.get('role', 'all')}
    return None
def list_users():
    with SessionLocal() as s:
        users = s.scalars(select(User).order_by(User.username)).all()
        return [{'id': u.id, 'username': u.username, 'created_at': u.created_at, 'role': u.role or 'all'} for u in users]
def create_user(username, password, role='agendamento'):
    username = (username or '').strip()
    if not username:
        raise ValueError("Nome de usuario nao pode ser vazio.")
    if not password or len(password) < 8:
        raise ValueError("A senha precisa ter pelo menos 8 caracteres.")
    if get_user_by_username(username):
        raise ValueError("Esse nome de usuario ja existe.")
    with SessionLocal() as s:
        if role not in ('agendamento', 'confirmacao', 'all', 'admin'):
            role = 'agendamento'
        u = User(username=username, password_hash=generate_password_hash(password), role=role)
        s.add(u)
        s.commit()
        s.refresh(u)
        return u.id
def change_password(user_id, new_password):
    if not new_password or len(new_password) < 8:
        raise ValueError("A senha precisa ter pelo menos 8 caracteres.")
    with SessionLocal() as s:
        s.execute(
            update(User).where(User.id == user_id)
            .values(password_hash=generate_password_hash(new_password))
        )
        s.commit()
def delete_user(user_id):
    with SessionLocal() as s:
        s.execute(delete(User).where(User.id == user_id))
        s.commit()
def count_users():
    with SessionLocal() as s:
        return s.scalar(select(func.count(User.id)))
# ---- Employees --------------------------------------------------------------
def get_employees(unit=None, active=None):
    with SessionLocal() as s:
        q = select(Employee)
        if unit:
            q = q.where(Employee.unit == unit)
        if active is not None:
            q = q.where(Employee.active == (1 if active else 0))
        q = q.order_by(Employee.name)
        rows = s.scalars(q).all()
        return [{'id': r.id, 'name': r.name, 'unit': r.unit, 'active': r.active, 'funcao': (r.funcao or 'ATENDENTE')} for r in rows]
def create_employee(name, unit, active=True, funcao='ATENDENTE'):
    with SessionLocal() as s:
        e = Employee(name=name, unit=unit, active=1 if active else 0, funcao=funcao)
        s.add(e)
        s.commit()
        s.refresh(e)
        return e.id
def deactivate_employee(eid):
    with SessionLocal() as s:
        s.execute(update(Employee).where(Employee.id == eid).values(active=0))
        s.commit()
def delete_employee_hard(eid):
    with SessionLocal() as s:
        s.execute(delete(Employee).where(Employee.id == eid))
        s.commit()
# ---- Appointments -----------------------------------------------------------
def get_appointment(unit, date):
    with SessionLocal() as s:
        a = s.scalar(select(Appointment).where(
            and_(Appointment.unit == unit, Appointment.date == date)
        ))
        return _appt_to_dict(a) if a else None
def get_appointments_by_date(date):
    with SessionLocal() as s:
        rows = s.scalars(select(Appointment).where(Appointment.date == date)).all()
        return [_appt_to_dict(r) for r in rows]
def get_appointments_by_month(year, month):
    start = f"{year:04d}-{month:02d}-01"
    if month == 12:
        end = f"{year + 1:04d}-01-01"
    else:
        end = f"{year:04d}-{month + 1:02d}-01"
    with SessionLocal() as s:
        rows = s.scalars(
            select(Appointment)
            .where(and_(Appointment.date >= start, Appointment.date < end))
            .order_by(Appointment.date)
        ).all()
        return [_appt_to_dict(r) for r in rows]
def upsert_appointment(unit, date, leader, rows_list):
    payload = json.dumps(rows_list, ensure_ascii=False)
    with SessionLocal() as s:
        existing = s.scalar(select(Appointment).where(
            and_(Appointment.unit == unit, Appointment.date == date)
        ))
        if existing:
            s.execute(
                update(Appointment)
                .where(and_(Appointment.unit == unit, Appointment.date == date))
                .values(leader=leader, rows=payload)
            )
        else:
            s.add(Appointment(unit=unit, date=date, leader=leader, rows=payload))
        s.commit()
def update_comparecimento(unit, date, comparecimento_data):
    payload = json.dumps(comparecimento_data, ensure_ascii=False)
    with SessionLocal() as s:
        s.execute(
            update(Appointment)
            .where(and_(Appointment.unit == unit, Appointment.date == date))
            .values(comparecimento_data=payload)
        )
        s.commit()
def clear_appointment(unit, date):
    with SessionLocal() as s:
        s.execute(delete(Appointment).where(
            and_(Appointment.unit == unit, Appointment.date == date)
        ))
        s.commit()
# ---- Role management --------------------------------------------------------
def set_user_role(user_id, role):
    allowed = ('agendamento', 'confirmacao', 'all', 'admin')
    if role not in allowed:
        raise ValueError(f'Role invalido. Use: {allowed}')
    with SessionLocal() as s:
        s.execute(update(User).where(User.id == user_id).values(role=role))
        s.commit()
# ---- Confirmacoes -----------------------------------------------------------
def _conf_to_dict(c):
    return {
        'id': c.id, 'atendente': c.atendente or '', 'mes': c.mes, 'data_str': c.data_str,
        'cliente': c.cliente, 'tmk': c.tmk, 'unidade': c.unidade,
        'horario': c.horario, 'contato': c.contato, 'flag': c.flag,
        'observacao': c.observacao or '',
        'created_at': c.created_at,
    }
def get_confirmacoes(mes=None, data_str=None, tmk=None, atendente=None):
    with SessionLocal() as s:
        q = select(Confirmacao).order_by(Confirmacao.data_str, Confirmacao.horario, Confirmacao.id)
        if atendente:
            q = q.where(Confirmacao.atendente == atendente)
        if mes:
            q = q.where(Confirmacao.mes == mes)
        if data_str:
            q = q.where(Confirmacao.data_str == data_str)
        if tmk:
            q = q.where(Confirmacao.tmk.ilike(f'%{tmk}%'))
        return [_conf_to_dict(r) for r in s.scalars(q).all()]
def create_confirmacao(data):
    with SessionLocal() as s:
        c = Confirmacao(**{k: v for k, v in data.items() if k in
            ('atendente','mes','data_str','cliente','tmk','unidade','horario','contato','flag','observacao')})
        s.add(c)
        s.commit()
        s.refresh(c)
        return c.id
def update_confirmacao(cid, data):
    allowed = ('atendente','mes','data_str','cliente','tmk','unidade','horario','contato','flag','observacao')
    vals = {k: v for k, v in data.items() if k in allowed}
    if not vals:
        return
    with SessionLocal() as s:
        s.execute(update(Confirmacao).where(Confirmacao.id == cid).values(**vals))
        s.commit()
def delete_confirmacao(cid):
    with SessionLocal() as s:
        s.execute(delete(Confirmacao).where(Confirmacao.id == cid))
        s.commit()
def bulk_insert_confirmacoes(rows):
    with SessionLocal() as s:
        for r in rows:
            c = Confirmacao(**{k: v for k, v in r.items() if k in
                ('atendente','mes','data_str','cliente','tmk','unidade','horario','contato','flag','observacao')})
            s.add(c)
        s.commit()
def clear_confirmacoes_dia(data_str, atendente=None):
    with SessionLocal() as s:
        q = delete(Confirmacao).where(Confirmacao.data_str == data_str)
        if atendente:
            q = q.where(Confirmacao.atendente == atendente)
        s.execute(q)
        s.commit()
# ---- Metas ------------------------------------------------------------------
def _meta_to_dict(m):
    return {
        'id': m.id, 'ano': m.ano, 'mes': m.mes,
        'unidade': m.unidade, 'bairro': m.bairro or '',
        'meta_agend': m.meta_agend or 0,
        'meta_comp': m.meta_comp or 0,
        'meta_dia': m.meta_dia or 0,
        'meta_hora': m.meta_hora or 0,
        'meta_conv': m.meta_conv or 0,
        'updated_at': m.updated_at or '',
    }
def get_metas(ano, mes):
    """Retorna todas as metas de um mês/ano (todas as unidades e bairros)."""
    with SessionLocal() as s:
        rows = s.scalars(
            select(Meta).where(and_(Meta.ano == ano, Meta.mes == mes))
        ).all()
        return [_meta_to_dict(r) for r in rows]
def upsert_meta(ano, mes, unidade, bairro, meta_agend, meta_comp, meta_conv):
    """Cria ou atualiza a meta de uma unidade/bairro para um mês/ano."""
    bairro = bairro or ''
    now = datetime.utcnow().isoformat()
    with SessionLocal() as s:
        existing = s.scalar(select(Meta).where(and_(
            Meta.ano == ano, Meta.mes == mes,
            Meta.unidade == unidade, Meta.bairro == bairro
        )))
        if existing:
            s.execute(
                update(Meta).where(Meta.id == existing.id).values(
                    meta_agend=meta_agend, meta_comp=meta_comp,
                    meta_conv=meta_conv, updated_at=now
                )
            )
        else:
            s.add(Meta(
                ano=ano, mes=mes, unidade=unidade, bairro=bairro,
                meta_agend=meta_agend, meta_comp=meta_comp,
                meta_conv=meta_conv, updated_at=now
            ))
        s.commit()
def bulk_upsert_metas(ano, mes, metas_list):
    """Salva várias metas de uma vez (cada item: unidade, bairro, meta_agend, meta_comp, meta_conv)."""
    now = datetime.utcnow().isoformat()
    with SessionLocal() as s:
        for m in metas_list:
            unidade = m.get('unidade', '')
            bairro  = m.get('bairro', '') or ''
            if not unidade:
                continue
            ag   = int(m.get('meta_agend') or 0)
            comp = int(m.get('meta_comp') or 0)
            dia  = float(m.get('meta_dia') or 0)
            hora = float(m.get('meta_hora') or 0)
            conv = int(m.get('meta_conv') or 0)
            existing = s.scalar(select(Meta).where(and_(
                Meta.ano == ano, Meta.mes == mes,
                Meta.unidade == unidade, Meta.bairro == bairro
            )))
            if existing:
                s.execute(
                    update(Meta).where(Meta.id == existing.id).values(
                        meta_agend=ag, meta_comp=comp, meta_dia=dia, meta_hora=hora, meta_conv=conv, updated_at=now
                    )
                )
            else:
                s.add(Meta(
                    ano=ano, mes=mes, unidade=unidade, bairro=bairro,
                    meta_agend=ag, meta_comp=comp, meta_dia=dia, meta_hora=hora, meta_conv=conv, updated_at=now
                ))
        s.commit()
# ---- Estatísticas públicas (para a landing) ---------------------------------
def get_stats_publicas():
    """Retorna os totais gerais (todos os tempos) para exibir na landing pública:
    leads recebidos, agendamentos feitos e comparecimentos.
    Não expõe nenhum dado individual — apenas os 3 totais somados."""
    LEADS_PREFIX = "LEADS::"
    LEAD_KEYS = ['wbp_lead', 'vbot_lead', 'antigos_lead', 'mkt_lead', 'whats_lead', 'mabe_lead']
    total_leads = 0
    total_agend = 0
    total_comp = 0
    with SessionLocal() as s:
        rows = s.scalars(select(Appointment)).all()
        for a in rows:
            unit = a.unit or ''
            rows_list = _safe_json_loads(a.rows, [])
            if unit.startswith(LEADS_PREFIX):
                # Linhas de leads: soma as chaves de lead de cada pessoa
                for r in rows_list:
                    lead_data = (r.get('lead') or {}) if isinstance(r, dict) else {}
                    total_leads += sum(int(lead_data.get(k) or 0) for k in LEAD_KEYS)
            else:
                # Agendamentos normais: soma os slots das pessoas com nome
                for r in rows_list:
                    if isinstance(r, dict) and (r.get('name') or '').strip():
                        slots = r.get('slots') or {}
                        for v in slots.values():
                            try:
                                total_agend += int(v or 0)
                            except (ValueError, TypeError):
                                pass
                # Comparecimentos: soma comparecimento_data (ignora __bairros__)
                comp_data = _safe_json_loads(a.comparecimento_data, {})
                for k, v in comp_data.items():
                    if k == '__bairros__':
                        continue
                    try:
                        total_comp += int(v or 0)
                    except (ValueError, TypeError):
                        pass
    return {'leads': total_leads, 'agendamentos': total_agend, 'comparecimentos': total_comp}
