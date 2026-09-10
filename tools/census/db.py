"""APTrace census: SQLite connection/schema helper.

One database file per repo (default: research/runs/census/census.sqlite3),
covering every firmware image the census has been run against -- rows are
scoped by `firmware_id`, not by one-database-per-image, so a query like
"which functions have never executed in any known scenario" can compare
across firmware if ever needed, even though every current query is
firmware-scoped.

Plain stdlib sqlite3, no ORM -- matches this project's existing
"flat script, stdlib only" convention (see tools/ghidra/aptrace_ghidra.py,
tools/unicorn/concrete.py).
"""
import sqlite3
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
SCHEMA_PATH = HERE / "schema.sql"
DEFAULT_DB_PATH = REPO_ROOT / "research" / "runs" / "census" / "census.sqlite3"


def connect(db_path=None, create=True):
    """Open (creating parent dirs + schema if needed) the census
    database. Does NOT create the file if create=False and it doesn't
    exist yet -- callers that only read (the query CLI) should pass
    create=False so a typo'd/missing path fails loudly instead of
    silently producing an empty database."""
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    if not create and not path.exists():
        raise FileNotFoundError(
            f"no census database at {path} -- run 'aptrace_census.py build <firmware>' first")
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn):
    have_tables = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    if "firmware" in have_tables:
        return
    conn.executescript(SCHEMA_PATH.read_text())
    conn.commit()


def get_firmware_id(conn, key):
    row = conn.execute("SELECT id FROM firmware WHERE key = ?", (key,)).fetchone()
    if row is None:
        raise ValueError(f"firmware '{key}' has no census in this database yet -- "
                          f"run 'aptrace_census.py build {key}' first")
    return row["id"]


# Every per-firmware table except `firmware` itself, in an order safe to
# DELETE from top-to-bottom (children before the parents they reference)
# -- see clear_firmware_data. Keep in sync with schema.sql's FOREIGN KEYs.
_TABLES_CHILD_FIRST = (
    "dynamic_tx_rx", "dynamic_mmio", "dynamic_memory", "dynamic_coverage", "dynamic_runs",
    "pins", "mmio_accesses", "memory_accesses", "literal_refs", "edges", "basic_blocks",
    "function_pointers", "vectors", "strings", "peripherals", "scan_warnings", "functions",
)


def clear_firmware_data(conn, firmware_id):
    """Delete every row for this firmware across every table (but NOT the
    `firmware` row itself), in dependency order -- must run before
    build.py re-inserts `functions`/`basic_blocks`, since every other
    table's rows reference them by id and a plain per-table
    DELETE-then-INSERT (replace_firmware_rows) would otherwise violate
    the foreign-key constraints the moment it reaches `functions`.
    Also means a static rebuild invalidates any previously-ingested
    dynamic coverage (its function_id/basic_block_id attributions would
    otherwise point at rows that no longer exist) -- re-run
    `ingest-dynamic` after `build`."""
    for table in _TABLES_CHILD_FIRST:
        conn.execute(f"DELETE FROM {table} WHERE firmware_id = ?", (firmware_id,))
    conn.commit()


def replace_firmware_rows(conn, firmware_id, table, rows):
    """Delete every existing row for this firmware in `table`, then
    insert `rows` (a list of dicts, all sharing the same key set) --
    used by build.py so a re-run of `census build` is idempotent
    (reflects the current Ghidra/Unicorn/SVD state exactly, not a union
    with whatever a prior build happened to find) rather than
    accumulating duplicate rows across rebuilds."""
    conn.execute(f"DELETE FROM {table} WHERE firmware_id = ?", (firmware_id,))
    if not rows:
        return
    cols = list(rows[0].keys())
    placeholders = ", ".join("?" for _ in cols)
    col_list = ", ".join(cols)
    conn.executemany(
        f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})",
        [tuple(r[c] for c in cols) for r in rows],
    )
