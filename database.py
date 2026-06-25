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
import json
from datetime import datetime

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

# No Vercel, usa pg8000 (driver Python puro, sem dependencias nativas).
# Localmente, mantém psycopg2 se disponivel; cai para pg8000 se nao.
is_serverless = os.environ.get('VERCEL') or os.environ.get('VERCEL_ENV')
if is_serverless and 'postgresql' in DATABASE_URL and 'pg8000' not in DATABASE_URL:
    # Remove qualquer driver explicito e usa pg8000
    import re
    DATABASE_URL = re.sub(r'postgresql\+\w+://', 'postgresql+pg8000://', DATABASE_URL)
    if 'postgresql+pg8000://' not in DATABASE_URL:
        DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+pg8000://')

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
    role          = Column(String(50), default='all')  # 'agendamento', 'confirmacao', 'all'
    created_at    = Column(String(40),  default=lambda: datetime.utcnow().isoformat())
    __table_args__ = (
        Index('idx_users_username', 'username'),
    )


class Confirmacao(Base):
    __tablename__ = 'confirmacoes'
    id       = Column(Integer, primary_key=True, autoincrement=True)
    mes      = Column(String(20),  default='')
    data_str = Column(String(10),  default='')   # DD/MM/YYYY
    cliente  = Column(String(300), default='')
    tmk      = Column(String(200), default='')
    unidade  = Column(String(100), default='')
    horario  = Column(String(20),  default='')
    contato  = Column(String(100), default='')
    flag     = Column(String(100), default='')
    created_at = Column(String(40), default=lambda: datetime.utcnow().isoformat())
    __table_args__ = (
        Index('idx_conf_mes', 'mes'),
        Index('idx_conf_data', 'data_str'),
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
        # Migração 1: adiciona coluna 'role' na tabela users se não existir
        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT 'all'"))
            conn.commit()
            print("[migration] Coluna 'role' adicionada à tabela users.")
        except Exception:
            pass  # Coluna já existe, ignora

        # Migração 2: cria tabela confirmacoes se não existir (já feito pelo create_all, mas garante)
        pass


def ensure_default_admin():
    """Se nao houver nenhum usuario, cria o admin inicial.
    Senha: usa ADMIN_PASS do ambiente; se ausente, gera uma aleatória forte
    em produção (PostgreSQL) ou usa um padrão de dev (que deve ser trocado)."""
    import secrets
    with SessionLocal() as s:
        n = s.scalar(select(func.count(User.id)))
        if n == 0:
            senha = DEFAULT_ADMIN_PASS
            gerada = False
            if not senha:
                if not DATABASE_URL.startswith('sqlite'):
                    # Produção sem ADMIN_PASS: senha aleatória forte
                    senha = secrets.token_urlsafe(12)
                    gerada = True
                else:
                    # Dev: padrão temporário
                    senha = 'trocar-senha-123'
            s.add(User(
                username=DEFAULT_ADMIN_USER,
                password_hash=generate_password_hash(senha),
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
        return {'id': user['id'], 'username': user['username']}
    return None


def list_users():
    with SessionLocal() as s:
        users = s.scalars(select(User).order_by(User.username)).all()
        return [{'id': u.id, 'username': u.username, 'created_at': u.created_at, 'role': u.role or 'all'} for u in users]


def create_user(username, password):
    username = (username or '').strip()
    if not username:
        raise ValueError("Nome de usuario nao pode ser vazio.")
    if not password or len(password) < 8:
        raise ValueError("A senha precisa ter pelo menos 8 caracteres.")
    if get_user_by_username(username):
        raise ValueError("Esse nome de usuario ja existe.")
    with SessionLocal() as s:
        u = User(username=username, password_hash=generate_password_hash(password))
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
        return [{'id': r.id, 'name': r.name, 'unit': r.unit, 'active': r.active} for r in rows]


def create_employee(name, unit, active=True):
    with SessionLocal() as s:
        e = Employee(name=name, unit=unit, active=1 if active else 0)
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
    allowed = ('agendamento', 'confirmacao', 'all')
    if role not in allowed:
        raise ValueError(f'Role invalido. Use: {allowed}')
    with SessionLocal() as s:
        s.execute(update(User).where(User.id == user_id).values(role=role))
        s.commit()


# ---- Confirmacoes -----------------------------------------------------------

def _conf_to_dict(c):
    return {
        'id': c.id, 'mes': c.mes, 'data_str': c.data_str,
        'cliente': c.cliente, 'tmk': c.tmk, 'unidade': c.unidade,
        'horario': c.horario, 'contato': c.contato, 'flag': c.flag,
        'created_at': c.created_at,
    }


def get_confirmacoes(mes=None, data_str=None, tmk=None):
    with SessionLocal() as s:
        q = select(Confirmacao).order_by(Confirmacao.data_str, Confirmacao.horario, Confirmacao.id)
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
            ('mes','data_str','cliente','tmk','unidade','horario','contato','flag')})
        s.add(c)
        s.commit()
        s.refresh(c)
        return c.id


def update_confirmacao(cid, data):
    allowed = ('mes','data_str','cliente','tmk','unidade','horario','contato','flag')
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
                ('mes','data_str','cliente','tmk','unidade','horario','contato','flag')})
            s.add(c)
        s.commit()


def clear_confirmacoes_dia(data_str):
    with SessionLocal() as s:
        s.execute(delete(Confirmacao).where(Confirmacao.data_str == data_str))
        s.commit()
