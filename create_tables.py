"""
Script para criar as tabelas no banco de producao (Supabase/PostgreSQL).
Execute UMA VEZ, localmente, antes do primeiro deploy:

    DATABASE_URL="postgresql+psycopg2://..." python create_tables.py

Nao precisa rodar no Vercel.
"""
import os
import sys

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    print("ERRO: defina DATABASE_URL antes de rodar este script.")
    print("Exemplo:")
    print('  DATABASE_URL="postgresql+psycopg2://user:pass@host:5432/db" python create_tables.py')
    sys.exit(1)

if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

os.environ['DATABASE_URL'] = DATABASE_URL

import database as db

print("Conectando ao banco...")
print(f"URL: {DATABASE_URL[:40]}...")
db.Base.metadata.create_all(db.engine)
db._run_migrations()
db.ensure_default_admin()
print("Tabelas criadas com sucesso!")
