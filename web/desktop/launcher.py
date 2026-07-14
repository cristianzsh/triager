#!/usr/bin/env python3
"""
Triager Console launcher.

Runs the same way in two situations:
  1. Dev, from source, on Linux or Windows: python3 desktop/launcher.py
  2. The packaged Windows executable (built via desktop/build_windows.bat),
     double-clicked or run from a terminal with arguments

(Packaging is Windows-only, since Triager itself is currently only built
for Windows. The unpackaged app still runs fine on Linux for development,
or to host the console with only the "already-processed" ingestion path
available.)

Starts the same FastAPI/uvicorn server used in dev, binds to localhost by
default, and opens the investigator's normal web browser to it, no
embedded browser engine, no extra runtime dependency beyond what's already
needed to run the API.

Usage:
    python3 desktop/launcher.py [--port 8000] [--host 127.0.0.1] [--no-browser]

    TriagerWeb.exe [--port 8000] [--host 127.0.0.1] [--no-browser]

Binding to anything other than 127.0.0.1/localhost automatically serves
over HTTPS with a self-signed certificate (generated once, reused after),
since traffic would otherwise leave the machine unencrypted.
"""
import argparse
import ctypes
import datetime as dt
import ipaddress
import os
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

# When frozen (PyInstaller), the backend package is bundled at the app
# root (sys._MEIPASS for --onefile, the exe's own folder for --onedir);
# when run from source, it lives at ../backend relative to this file.
# This mirrors runtime_paths.bundle_dir()'s exact frozen-detection logic,
# duplicated here rather than imported, since sys.path isn't set up yet at
# this point to import anything from the app package.
if getattr(sys, "frozen", False):
    _APP_ROOT = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
else:
    _APP_ROOT = Path(__file__).resolve().parent.parent / "backend"

if str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))


# Console color handling
# Windows consoles (cmd.exe, older PowerShell) don't interpret ANSI escape
# codes unless VT100 processing is explicitly turned on, without this,
# uvicorn's own colored log output (and the banner below) shows up as raw
# "\x1b[32m...\x1b[0m" garbage instead of color. This mirrors the exact
# technique Triager's own CLI uses for the same reason on Windows.
def _enable_windows_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        # Cheap, well-known fallback: on Windows, invoking a subshell via
        # os.system() has the side effect of initializing the console host
        # in a way that often enables ANSI processing on its own, via a
        # different code path than the explicit SetConsoleMode call below.
        # Harmless no-op command; do this regardless of whether the ctypes
        # approach below succeeds.
        os.system("")
    except Exception:
        pass

    try:
        kernel32 = ctypes.windll.kernel32

        # Without explicit argtypes/restype, ctypes assumes GetStdHandle
        # returns a 32-bit C int, but HANDLE is pointer-sized (64-bit on
        # 64-bit Windows, i.e. essentially every modern install). That
        # truncates the real handle value, so every GetConsoleMode/
        # SetConsoleMode call afterward silently operates on a corrupted
        # handle and fails, which is exactly why enabling VT mode kept
        # not working even though the code "looked" like it should.
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        kernel32.GetStdHandle.argtypes = [ctypes.c_uint32]
        kernel32.GetConsoleMode.restype = ctypes.c_int
        kernel32.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        kernel32.SetConsoleMode.restype = ctypes.c_int
        kernel32.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

        ok = True
        for handle_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            handle = kernel32.GetStdHandle(handle_id)
            if not handle or handle == -1:
                continue
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                ok = False
                continue
            if not kernel32.SetConsoleMode(handle, mode.value | 0x0004):  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                ok = False
        return ok
    except Exception:
        return False


_USE_COLOR = _enable_windows_ansi() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def _green(text: str) -> str:
    return _c("92", text)


def _yellow(text: str) -> str:
    return _c("93", text)


def _cyan(text: str) -> str:
    return _c("96", text)


def _bold(text: str) -> str:
    return _c("1", text)


def _is_loopback(host: str) -> bool:
    return host in ("127.0.0.1", "localhost", "::1")


def _ensure_self_signed_cert(cert_dir: Path, host: str) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"

    if cert_path.exists() and key_path.exists():
        try:
            existing = x509.load_pem_x509_certificate(cert_path.read_bytes())
            if existing.not_valid_after_utc > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1):
                return cert_path, key_path
        except Exception:
            pass

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Triager Console")])

    san = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    try:
        ip = ipaddress.ip_address(host)
        if str(ip) not in ("127.0.0.1",):
            san.append(x509.IPAddress(ip))
    except ValueError:
        if host not in ("localhost",):
            san.append(x509.DNSName(host))

    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="TriagerWeb",
        description="Starts the Triager Console web server and opens it in your browser.",
    )
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Address to bind to (default: 127.0.0.1 -- localhost only). "
             "Anything else automatically serves over HTTPS with a self-signed cert."
    )
    parser.add_argument("--no-browser", action="store_true", help="Don't automatically open a browser tab")
    parser.add_argument(
        "--data-dir", default=None,
        help="Override where case data/uploads/the app database are stored "
             "(default: a 'data' folder next to this program)",
    )
    return parser.parse_args()


def _wait_for_server(url: str, timeout: float = 20.0, verify_tls: bool = True) -> bool:
    import ssl
    context = None if verify_tls else ssl._create_unverified_context()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1, context=context)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def _print_banner(host: str, port: int, https: bool) -> None:
    display_host = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
    scheme = "https" if https else "http"
    url = f"{scheme}://{display_host}:{port}"

    print()
    print(_bold(_cyan("=" * 60)))
    print(_bold(_cyan("  Triager Console")))
    print(_bold(_cyan("=" * 60)))
    print(f"  Open in your browser: {_green(_bold(url))}")
    print(f"  Press Ctrl+C here to stop the server.")
    print()

    if _is_loopback(host):
        print(_c("90", "  Running on localhost only"))
    else:
        print(_yellow("  NOTE: bound to " + host + ", not just localhost!"))
        print(_c("90", "  Using a self-signed TLS certificate -- your browser will warn"))
        print(_c("90", "  about it once; that's expected for a self-signed cert."))
    print()


def main() -> None:
    args = parse_args()

    if args.data_dir:
        os.environ.setdefault("TRIAGER_WEB_STORAGE_ROOT", str(Path(args.data_dir).resolve() / "storage"))
        os.environ.setdefault(
            "TRIAGER_WEB_APP_DB_URL",
            f"sqlite:///{(Path(args.data_dir).resolve() / 'triager_app.db').as_posix()}",
        )

    import uvicorn
    from app.main import app  # noqa: E402
    from app.runtime_paths import writable_data_dir

    ssl_kwargs = {}
    https = not _is_loopback(args.host)
    if https:
        cert_dir = (Path(args.data_dir).resolve() if args.data_dir else writable_data_dir()) / "certs"
        cert_path, key_path = _ensure_self_signed_cert(cert_dir, args.host)
        ssl_kwargs = {"ssl_certfile": str(cert_path), "ssl_keyfile": str(key_path)}

    _print_banner(args.host, args.port, https)

    if not args.no_browser:
        scheme = "https" if https else "http"
        display_host = "127.0.0.1" if args.host == "0.0.0.0" else args.host
        health_url = f"{scheme}://{display_host}:{args.port}/api/health"
        browser_url = f"{scheme}://{display_host}:{args.port}"

        def _open_when_ready():
            if _wait_for_server(health_url, verify_tls=not https):
                webbrowser.open(browser_url)

        threading.Thread(target=_open_when_ready, daemon=True).start()

    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info", use_colors=_USE_COLOR, **ssl_kwargs)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
