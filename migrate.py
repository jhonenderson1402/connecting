"""
migrate.py — Aplica migrações necessárias no banco existente.
Execute UMA VEZ antes de reiniciar o servidor:

    python migrate.py
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'agendamentos.db')

def migrate():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Verifica colunas existentes na tabela users
    cur.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in cur.fetchall()]
    print(f"Colunas atuais em 'users': {cols}")

    # Migração 1: adiciona coluna 'role'
    if 'role' not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT 'all'")
        cur.execute("UPDATE users SET role = 'all' WHERE role IS NULL")
        conn.commit()
        print("✅ Coluna 'role' adicionada com sucesso!")
    else:
        print("ℹ️  Coluna 'role' já existe.")

    # Migração 2: cria tabela confirmacoes
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='confirmacoes'")
    if not cur.fetchone():
        cur.execute("""
            CREATE TABLE confirmacoes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mes VARCHAR(20) DEFAULT '',
                data_str VARCHAR(10) DEFAULT '',
                cliente VARCHAR(300) DEFAULT '',
                tmk VARCHAR(200) DEFAULT '',
                unidade VARCHAR(100) DEFAULT '',
                horario VARCHAR(20) DEFAULT '',
                contato VARCHAR(100) DEFAULT '',
                flag VARCHAR(100) DEFAULT '',
                created_at VARCHAR(40) DEFAULT ''
            )
        """)
        conn.commit()
        print("✅ Tabela 'confirmacoes' criada com sucesso!")
    else:
        print("ℹ️  Tabela 'confirmacoes' já existe.")

    conn.close()
    print("\n✅ Migração concluída! Agora reinicie o servidor com: python app.py")

if __name__ == '__main__':
    migrate()
