import os
import hmac
import shutil
import json
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest, urlopen

from flask import Flask, abort, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.wrappers import Request, Response

from content import SITE_DATA
from stats_service import (
    build_dashboard_data,
    build_raw_events_data,
    get_import_options,
    import_plaintext_source,
)


def _load_local_env(project_root: Path) -> None:
    env_path = project_root / ".env.local"
    if not env_path.exists():
        return

    try:
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, value)
    except OSError:
        return


def _get_int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default

    try:
        return int(raw_value)
    except ValueError:
        try:
            float_value = float(raw_value)
        except ValueError:
            return default
        if float_value.is_integer():
            return int(float_value)
        return default


def _build_split_prompt(is_pdf: bool) -> str:
    if is_pdf:
        return """You are reading a Danish Betalingsservice document. Extract ONLY shared household expenses.
INCLUDE: husleje, basisleje, leje, el, strom, gas, internet, vand, varme, A/C varme, tv/antenne, licens, indboforsikring, ejendomsforsikring, streaming, abonnementer, postkasser, faellesudgifter. For bundled rent entries (e.g. Frederiksberg Alle) that show basisleje + varme + postkasser etc., use the single IALT/total shown for that creditor entry.
EXCLUDE: AL Finans, Clever A/S, PROSA, Louis Nielsen, PRIVATSIKRING, motor/bilforsikring, rejseforsikring, ulykkesforsikring, kontaktlinser, lanefinansiering, ydelse, kontogebyr, depositum, forudbetalt leje, MASTERCARD, opkraevningsgebyr.
Return ONLY JSON: [{"name":"...","amount":0}] with dot decimals. If nothing qualifies return []."""
    return """You are reading a Danish Betalingsservice document. Extract ONLY shared household expenses.
INCLUDE: husleje, basisleje, leje, el, strom, gas, internet, vand, varme, A/C varme, tv/antenne, licens, indboforsikring, ejendomsforsikring, streaming, abonnementer, postkasser, faellesudgifter. For bundled rent entries (e.g. Frederiksberg Alle) use the IALT/total for that creditor.
EXCLUDE: AL Finans, Clever A/S, PROSA, Louis Nielsen, PRIVATSIKRING, motor/bilforsikring, rejseforsikring, ulykkesforsikring, kontaktlinser, lanefinansiering, ydelse, kontogebyr, depositum, forudbetalt leje, MASTERCARD.
Return ONLY JSON: [{"name":"...","amount":0}] with dot decimals."""


def _extract_split_text_output(payload: dict[str, Any]) -> str:
    output_text = payload.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text

    for item in payload.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                return content["text"]
    return "[]"


def _coerce_split_amount(value: Any) -> Optional[float]:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None

    candidate = value.strip().replace(" ", "")
    if not candidate:
        return None

    has_comma = "," in candidate
    has_dot = "." in candidate
    if has_comma and has_dot:
        if candidate.rfind(",") > candidate.rfind("."):
            candidate = candidate.replace(".", "").replace(",", ".")
        else:
            candidate = candidate.replace(",", "")
    elif has_comma:
        candidate = candidate.replace(".", "").replace(",", ".")
    else:
        candidate = candidate.replace(",", "")

    try:
        return float(candidate)
    except ValueError:
        return None


def _resolve_stats_dir(project_root: Path) -> Path:
    configured = os.getenv("STATS_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()

    # App Service deployments commonly mount the app package as read-only.
    # Use the persistent data volume by default when running on Azure.
    if os.getenv("WEBSITE_SITE_NAME", "").strip():
        return Path("/home/site/data/stats")

    return project_root / "stats"


def _normalize_login_secret(raw_value: str) -> str:
    return raw_value.strip().strip("/")


def _seed_stats_dir(stats_dir: Path, bundled_stats_dir: Path) -> None:
    if not bundled_stats_dir.exists() or not bundled_stats_dir.is_dir():
        return

    try:
        same_dir = stats_dir.resolve() == bundled_stats_dir.resolve()
    except OSError:
        same_dir = stats_dir == bundled_stats_dir
    if same_dir:
        return

    try:
        stats_dir.mkdir(parents=True, exist_ok=True)
        if any(stats_dir.iterdir()):
            return
    except OSError:
        return

    for item in bundled_stats_dir.iterdir():
        if not item.is_file():
            continue
        target = stats_dir / item.name
        try:
            shutil.copy2(item, target)
        except OSError:
            # Best effort: continue if a single file cannot be copied.
            continue


class _AuthRequiredMiddleware:
    def __init__(self, app: Flask, downstream, login_endpoint: str = "/login") -> None:
        self._app = app
        self._downstream = downstream
        self._login_endpoint = login_endpoint

    def __call__(self, environ, start_response):
        serializer = self._app.session_interface.get_signing_serializer(self._app)
        cookie_name = self._app.config["SESSION_COOKIE_NAME"]
        authenticated = False

        if serializer is not None:
            request = Request(environ)
            raw_cookie = request.cookies.get(cookie_name)
            if raw_cookie:
                max_age = int(self._app.permanent_session_lifetime.total_seconds())
                try:
                    data = serializer.loads(raw_cookie, max_age=max_age)
                except Exception:
                    data = {}
                authenticated = bool(
                    data.get("private_authenticated") or data.get("stats_authenticated")
                )

        if authenticated:
            return self._downstream(environ, start_response)

        request = Request(environ)
        current_path = f"{request.script_root}{request.path}"
        if request.query_string:
            current_path = f"{current_path}?{request.query_string.decode('utf-8', errors='ignore')}"
        login_location = f"{self._login_endpoint}?{urlencode({'next': current_path})}"
        response = Response("", status=302, headers={"Location": login_location})
        return response(environ, start_response)


def create_app() -> Flask:
    app = Flask(__name__)
    project_root = Path(__file__).resolve().parent
    split_dist_dir = project_root / "split_dist"
    _load_local_env(project_root)
    app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", os.getenv("SECRET_KEY", os.urandom(32)))
    # Trust Azure/App Service proxy headers for scheme/host/IP handling.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    bundled_stats_dir = project_root / "stats"
    stats_dir = _resolve_stats_dir(project_root)
    _seed_stats_dir(stats_dir=stats_dir, bundled_stats_dir=bundled_stats_dir)
    import_options = get_import_options()

    def _private_password() -> str:
        return os.getenv("PRIVATE_PASSWORD", os.getenv("STATS_PASSWORD", "")).strip()

    def _login_secret() -> str:
        return _normalize_login_secret(
            os.getenv("PRIVATE_LOGIN_SECRET", os.getenv("LOGIN_SECRET", ""))
        )

    def _login_url(next_path: str = "") -> str:
        params: dict[str, str] = {}
        if next_path:
            params["next"] = next_path
        return url_for("login_page", **params)

    def _signed_out_url(next_path: str = "") -> str:
        params: dict[str, str] = {}
        if next_path:
            params["next"] = next_path
        return url_for("signed_out_page", **params)

    def _safe_next_path(candidate: str) -> str:
        if not candidate:
            return url_for("private_nav")

        parsed = urlparse(candidate)
        if parsed.scheme or parsed.netloc:
            return url_for("private_nav")
        allowed_prefixes = ("/stats", "/split", "/nav")
        if candidate == "/login":
            return url_for("private_nav")
        if not candidate.startswith(allowed_prefixes):
            return url_for("private_nav")
        return candidate

    def _is_private_authenticated() -> bool:
        return bool(session.get("private_authenticated") or session.get("stats_authenticated"))

    @app.context_processor
    def inject_private_session_state():
        return {"private_session_authenticated": _is_private_authenticated()}

    def _private_auth_redirect():
        if not _private_password():
            abort(503, description="PRIVATE_PASSWORD or STATS_PASSWORD is not configured.")
        if _is_private_authenticated():
            return None

        next_target = request.full_path if request.query_string else request.path
        return redirect(_signed_out_url(next_target))

    def _import_context(
        feedback: Optional[Dict[str, str]] = None,
        selected_source: Optional[str] = None,
    ) -> Dict[str, object]:
        if feedback is None:
            feedback = session.pop("stats_import_feedback", None)
        if selected_source is None:
            selected_source = session.pop("stats_import_selected_source", "")
        if not selected_source and import_options:
            selected_source = import_options[0]["key"]
        return {
            "import_options": import_options,
            "import_feedback": feedback,
            "import_selected_source": selected_source,
        }

    @app.get("/")
    def home():
        return render_template("index.html", site=SITE_DATA)

    @app.get("/not-signed-in")
    def signed_out_page():
        return render_template(
            "not_signed_in.html",
            next_path=_safe_next_path(request.args.get("next", "")),
        )

    @app.get("/login")
    def login_page():
        secret = _normalize_login_secret(request.args.get("secret", ""))
        configured_secret = _login_secret()
        if not configured_secret or not hmac.compare_digest(secret, configured_secret):
            abort(404)

        if not _private_password():
            return render_template(
                "login.html",
                error="Set PRIVATE_PASSWORD or STATS_PASSWORD before opening this page.",
                next_path=url_for("private_nav"),
                login_secret=secret,
                password_configured=False,
            )

        if _is_private_authenticated():
            next_path = _safe_next_path(request.args.get("next", ""))
            return redirect(next_path if next_path != url_for("private_nav") else url_for("private_nav"))

        return render_template(
            "login.html",
            error=None,
            login_secret=secret,
            next_path=_safe_next_path(request.args.get("next", "")),
            password_configured=True,
        )

    @app.post("/login")
    def login_submit():
        submitted_secret = _normalize_login_secret(request.form.get("login_secret", ""))
        if not hmac.compare_digest(submitted_secret, _login_secret()):
            abort(404)

        configured_password = _private_password()
        if not configured_password:
            abort(503, description="PRIVATE_PASSWORD or STATS_PASSWORD is not configured.")

        candidate = request.form.get("password", "")
        next_path = _safe_next_path(request.form.get("next_path", ""))
        if hmac.compare_digest(candidate, configured_password):
            # Keep private access decisions in Flask's signed session cookie.
            session["private_authenticated"] = True
            session["stats_authenticated"] = True
            return redirect(next_path)

        return (
            render_template(
                "login.html",
                error="Wrong password.",
                login_secret=submitted_secret,
                next_path=next_path,
                password_configured=True,
            ),
            401,
        )

    @app.get("/nav")
    def private_nav():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        return render_template("nav.html")

    @app.get("/split")
    def split_entry():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect
        return redirect(url_for("split_frontend", path=""))

    @app.get("/split/api/health")
    def split_api_health():
        if not _is_private_authenticated():
            abort(401)
        return jsonify({"ok": True, "openaiConfigured": bool(os.getenv("OPENAI_API_KEY", "").strip())})

    @app.post("/split/api/extract-expenses")
    def split_api_extract_expenses():
        if not _is_private_authenticated():
            abort(401)

        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            return jsonify({"error": "OPENAI_API_KEY is not set."}), 500

        payload = request.get_json(silent=True) or {}
        data = payload.get("data")
        mime_type = payload.get("mimeType")
        kind = payload.get("kind")

        if not data or not mime_type or not kind:
            return jsonify({"error": "Missing data, mimeType, or kind."}), 400

        is_pdf = kind == "pdf"
        if is_pdf:
            user_content: list[dict[str, Any]] = [
                {
                    "type": "input_file",
                    "filename": "statement.pdf",
                    "file_data": f"data:{mime_type};base64,{data}",
                },
                {
                    "type": "input_text",
                    "text": "Extract shared household expenses. JSON only.",
                },
            ]
        else:
            user_content = [
                {
                    "type": "input_image",
                    "image_url": f"data:{mime_type};base64,{data}",
                },
                {
                    "type": "input_text",
                    "text": "Extract shared household expenses. JSON only.",
                },
            ]

        openai_payload = {
            "model": "gpt-4.1-mini",
            "input": [
                {
                    "role": "system",
                    "content": [{"type": "input_text", "text": _build_split_prompt(is_pdf)}],
                },
                {
                    "role": "user",
                    "content": user_content,
                },
            ],
        }

        try:
            api_request = UrlRequest(
                "https://api.openai.com/v1/responses",
                data=json.dumps(openai_payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                method="POST",
            )
            with urlopen(api_request, timeout=90) as response:
                response_payload = json.load(response)
        except HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            return jsonify({"error": f"OpenAI request failed: {details}"}), exc.code
        except URLError as exc:
            return jsonify({"error": f"OpenAI request failed: {exc.reason}"}), 502
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        text_block = _extract_split_text_output(response_payload)
        cleaned = text_block.replace("```json", "").replace("```", "").strip()

        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            return jsonify({"error": f"OpenAI returned invalid JSON: {text_block}"}), 502

        expense_items: Any = parsed
        if isinstance(parsed, dict):
            expense_items = parsed.get("expenses", [])

        expenses = []
        if isinstance(expense_items, list):
            for item in expense_items:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                amount = _coerce_split_amount(item.get("amount"))
                if isinstance(name, str) and amount is not None:
                    cleaned_name = name.strip()
                    if cleaned_name:
                        expenses.append({"name": cleaned_name, "amount": amount})

        return jsonify({"expenses": expenses})

    @app.get("/split/", defaults={"path": ""})
    @app.get("/split/<path:path>")
    def split_frontend(path: str):
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        if path.startswith("api/") or path == "healthz":
            abort(404)

        if split_dist_dir.exists():
            target = split_dist_dir / path
            if path and target.exists() and target.is_file():
                return send_from_directory(split_dist_dir, path)
            return send_from_directory(split_dist_dir, "index.html")

        abort(404)

    @app.post("/logout")
    def logout():
        session.pop("private_authenticated", None)
        session.pop("stats_authenticated", None)
        return redirect(_login_url())

    @app.get("/dans-penis")
    def dans_penis():
        art = """⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⣤⣤⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢰⡿⠋⠁⠀⠀⠈⠉⠙⠻⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣿⠇⠀⢀⣴⣶⡾⠿⠿⠿⢿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣀⣀⣸⡿⠀⠀⢸⣿⣇⠀⠀⠀⠀⠀⠀⠙⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣾⡟⠛⣿⡇⠀⠀⢸⣿⣿⣷⣤⣤⣤⣤⣶⣶⣿⠇⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀
⢀⣿⠀⢀⣿⡇⠀⠀⠀⠻⢿⣿⣿⣿⣿⣿⠿⣿⡏⠀⠀⠀⠀⢴⣶⣶⣿⣿⣿⣆
⢸⣿⠀⢸⣿⡇⠀⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⣿⡇⣀⣠⣴⣾⣮⣝⠿⠿⠿⣻⡟
⢸⣿⠀⠘⣿⡇⠀⠀⠀⠀⠀⠀⠀⣠⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠉⠀
⠸⣿⠀⠀⣿⡇⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠉⠀⠀⠀⠀
⠀⠻⣷⣶⣿⣇⠀⠀⠀⢠⣼⣿⣿⣿⣿⣿⣿⣿⣛⣛⣻⠉⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣿⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣿⣀⣀⣀⣼⡿⢿⣿⣿⣿⣿⣿⡿⣿⣿⣿"""
        return f"<pre>{art}</pre>"

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok"), 200

    @app.get("/stats/login")
    def stats_login():
        next_path = _safe_next_path(request.args.get("next", url_for("stats_page")))
        return redirect(_login_url(next_path))

    @app.post("/stats/login")
    def stats_login_submit():
        return login_submit()

    @app.post("/stats/logout")
    def stats_logout():
        return logout()

    @app.get("/stats")
    def stats_page():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        window = request.args.get("window", "90d")
        dashboard = build_dashboard_data(stats_dir=stats_dir, window=window)
        return render_template("stats.html", dashboard=dashboard)

    @app.get("/stats/dashboard")
    def stats_dashboard():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        window = request.args.get("window", "90d")
        dashboard = build_dashboard_data(stats_dir=stats_dir, window=window)
        return render_template("partials/stats_dashboard.html", dashboard=dashboard)

    @app.get("/stats/raw")
    def stats_raw():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        raw = build_raw_events_data(
            stats_dir=stats_dir,
            window=request.args.get("window", "90d"),
            source=request.args.get("source", "all"),
            day=request.args.get("day", ""),
            limit=request.args.get("limit", "120"),
        )
        return render_template("partials/stats_raw_table.html", raw=raw)

    @app.get("/stats/import")
    def stats_import_page():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        return render_template("stats_import.html", **_import_context())

    @app.post("/stats/import")
    def stats_import_plaintext():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        source = request.form.get("source", "").strip()
        payload = request.form.get("payload", "")
        selected_source = source if source else None

        try:
            result = import_plaintext_source(stats_dir=stats_dir, source=source, payload=payload)
            feedback = {
                "level": "ok",
                "text": (
                    "Imported {0} lines into {1}. "
                    "{2} unique events written ({3} non-event lines ignored)."
                ).format(
                    int(result["incoming_events"]),
                    str(result["target_file"]),
                    int(result["written_events"]),
                    int(result["ignored_lines"]),
                ),
            }
        except ValueError as exc:
            feedback = {"level": "error", "text": str(exc)}
        except OSError:
            feedback = {
                "level": "error",
                "text": "Could not write import file in {0}. Configure STATS_DIR to a writable path.".format(
                    stats_dir
                ),
            }

        session["stats_import_feedback"] = feedback
        if selected_source:
            session["stats_import_selected_source"] = selected_source
        return redirect(url_for("stats_import_page"))

    return app


app = create_app()


if __name__ == "__main__":
    from waitress import serve

    host = os.getenv("HOST", "localhost")
    port = _get_int_env("PORT", 8000)
    threads = _get_int_env("WAITRESS_THREADS", 8)
    print(f"Open: http://{host}:{port}")
    serve(app, host=host, port=port, threads=threads)
