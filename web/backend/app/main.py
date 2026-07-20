import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.types import Scope

from .database import Base, engine, SessionLocal
from .models import User, Role
from .security import hash_password
from .runtime_paths import bundle_dir
from .routers import auth, users, cases, machines, upload, jobs, artifacts, correlation, ai, audit, timeline, ioc_scan, report, findings, configs, triager_info, system

app = FastAPI(title="Triager Web", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production (reverse proxy / same-origin deployment recommended)
    allow_credentials=False,  # auth is a Bearer token, never a cookie, so this isn't needed
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    _bootstrap_admin()
    _warn_if_default_jwt_secret()


def _warn_if_default_jwt_secret():
    from .config import settings
    if settings.jwt_secret == "CHANGE_ME_IN_PRODUCTION":
        print("[!] WARNING: TRIAGER_WEB_JWT_SECRET is still the default placeholder.")
        print("[!] Every login token can be forged by anyone who reads the source.")
        print("[!] Set a real secret before exposing this beyond your own machine.")


def _bootstrap_admin():
    """Creates a first admin account on a fresh install. Credentials come
    from env vars; if unset, a random password is generated, logged, and
    written to a file next to the data dir (a --windowed build has no
    visible console, so stdout alone would lose it)."""
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return
        username = os.environ.get("TRIAGER_WEB_ADMIN_USER", "admin")
        password = os.environ.get("TRIAGER_WEB_ADMIN_PASSWORD")
        if not password:
            import secrets
            password = secrets.token_urlsafe(12)
            print("=" * 70)
            print(f"[bootstrap] Created initial admin user '{username}'")
            print(f"[bootstrap] Password: {password}")
            print("[bootstrap] Change this immediately after first login.")
            print("=" * 70)
            try:
                cred_file = settings.storage_root.parent / "FIRST_RUN_CREDENTIALS.txt"
                cred_file.write_text(
                    "Triager Console -- first-run admin credentials\n"
                    "Delete this file after logging in and changing the password.\n\n"
                    f"Username: {username}\nPassword: {password}\n",
                    encoding="utf-8",
                )
                print(f"[bootstrap] Also written to: {cred_file}")
            except Exception as ex:  # noqa: BLE001
                print(f"[bootstrap] Could not write credentials file: {ex}")
        admin = User(username=username, role=Role.admin, hashed_password=hash_password(password))
        db.add(admin)
        db.commit()
    finally:
        db.close()


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(cases.router)
app.include_router(machines.router)
app.include_router(upload.router)
app.include_router(jobs.router)
app.include_router(artifacts.router)
app.include_router(correlation.router)
app.include_router(ai.settings_router)
app.include_router(ai.router)
app.include_router(audit.router)
app.include_router(timeline.router)
app.include_router(ioc_scan.router)
app.include_router(report.router)
app.include_router(findings.router)
app.include_router(configs.router)
app.include_router(triager_info.router)
app.include_router(system.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


# Serve the (build-free, vanilla JS) frontend from the same origin so the
# investigator only needs one URL. In a hardened deployment, put this behind
# a reverse proxy (nginx/Caddy) with TLS instead.
class NoCacheStaticFiles(StaticFiles):
    """Plain StaticFiles lets browsers cache app.js/styles.css/index.html
    indefinitely with no revalidation -- a frontend update can silently
    keep serving a stale copy that 404s against renamed API routes,
    looking like a backend bug. Forces revalidation every request instead."""
    async def get_response(self, path: str, scope: Scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response


_frontend_dir = bundle_dir() / "frontend"
if _frontend_dir.exists():
    app.mount("/", NoCacheStaticFiles(directory=str(_frontend_dir), html=True), name="frontend")
