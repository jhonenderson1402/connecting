"""
cleanup.py — remove agendamentos com data inválida (ex: '2026-05-NaN').

Uso:
    python cleanup.py             # mostra o que seria removido (dry-run)
    python cleanup.py --apply     # remove de fato
"""
import sys
import sqlite3
from datetime import datetime

DB_PATH = 'agendamentos.db'


def main():
    apply_changes = '--apply' in sys.argv

    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, unit, date FROM appointments").fetchall()

    bad = []
    for rid, unit, date in rows:
        try:
            datetime.strptime(date, "%Y-%m-%d")
        except (ValueError, TypeError):
            bad.append((rid, unit, date))

    if not bad:
        print("✅ Nenhum registro inválido encontrado.")
        conn.close()
        return

    print(f"⚠️  Encontrados {len(bad)} registros com data inválida:")
    for rid, unit, date in bad:
        print(f"   id={rid}  unit={unit!r}  date={date!r}")

    if apply_changes:
        conn.executemany(
            "DELETE FROM appointments WHERE id=?",
            [(r[0],) for r in bad],
        )
        conn.commit()
        print(f"\n🗑️  Removidos {len(bad)} registros.")
    else:
        print("\n(dry-run) Rode novamente com --apply para remover de fato.")

    conn.close()


if __name__ == '__main__':
    main()
