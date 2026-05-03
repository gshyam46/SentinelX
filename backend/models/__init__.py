# SentinelX Models
# ─────────────────────────────────────────────────────────────────────────────
# ALL models must be imported here so SQLAlchemy's Base.metadata is fully
# populated (User + Scan + their FK relationship) before any worker, task, or
# Alembic command runs.  Celery prefork workers only import what celery_app.py
# loads — without these imports the ForeignKey("users.id") on Scan cannot be
# resolved, producing "could not find table 'users'" at query time.
from .user import User  # noqa: F401
from .scan import Scan  # noqa: F401
