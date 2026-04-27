"""
app.py — Aegis Security Backend  v3.1
======================================
Flask REST API server.

Routes
------
GET  /api/health                — health-check
POST /api/auth/test             — validate auth credentials before scanning ← NEW
POST /api/scan/crawl            — surface discovery only
POST /api/scan/payload          — injection assessment only
POST /api/scan/full             — full pipeline (crawl → inject → analyse → report)
GET  /api/report/<id>/html      — download HTML report
GET  /api/report/<id>/pdf       — download PDF report
GET  /api/report/<id>/summary   — JSON summary of a completed scan
"""

import os
import logging
from flask      import Flask, request, jsonify, send_file, abort
from flask_cors import CORS

from scanner.crawler        import Crawler
from scanner.payload_engine import PayloadEngine
from scanner.controller     import ScannerController
from scanner.auth_manager   import build_auth_manager, AuthManager

import json
from flask_swagger_ui import get_swaggerui_blueprint
from swagger import SWAGGER_SPEC

# ── App setup ────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [APP]  %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("app")

app = Flask(__name__)
CORS(app)

# ── Swagger UI setup ─────────────────────────────────────────

SWAGGER_URL  = '/api/docs'
API_SPEC_URL = '/api/swagger.json'

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_SPEC_URL,
    config={'app_name': "Aegis Security Platform"},
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)


@app.route('/api/swagger.json', methods=['GET'])
def swagger_spec():
    return app.response_class(
        response=json.dumps(SWAGGER_SPEC, indent=2),
        status=200,
        mimetype='application/json',
    )


REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

_scan_registry: dict = {}


# ── Helpers ──────────────────────────────────────────────────

def _validate_url(url: str):
    if not url:
        return None, (jsonify({"error": "Missing required field: target_url"}), 400)
    if not url.startswith(("http://", "https://")):
        return None, (jsonify({"error": "target_url must start with http:// or https://"}), 400)
    return url, None


def _resolve_auth(auth_config: dict):
    """
    Build an AuthManager from *auth_config*.
    Returns (session_or_None, label_str, detail_str).
    """
    if not auth_config:
        return None, "none", "No auth config provided"

    manager = build_auth_manager(auth_config)
    if manager and manager.is_authenticated:
        logger.info("[App] Auth configured: type=%s", manager.auth_type)
        return manager.get_session(), manager.auth_type or "unknown", "OK"

    logger.warning("[App] Auth config provided but login failed — continuing unauthenticated")
    return None, "failed", (
        "Login failed. Check credentials and ensure the target is reachable "
        "from inside the backend Docker container."
    )


# ── Health check ─────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status" : "ok",
        "service": "Aegis Security Platform",
        "modules": ["discovery", "injection", "analysis", "reporting"],
    }), 200


# ── Auth test  ← NEW in v3.1 ─────────────────────────────────

@app.route("/api/auth/test", methods=["POST"])
def test_auth():
    """
    Validate an auth configuration without running a scan.

    Request body
    ------------
    { "auth": { "type": "dvwa", "base_url": "...", ... } }

    Response  (HTTP 200 always — inspect the "success" field)
    ----------------------------------------------------------
    {
      "success"   : true | false,
      "auth_type" : "dvwa_form" | "cookie" | "failed" | ...,
      "cookies"   : { "PHPSESSID": "abc..." },
      "detail"    : "human-readable status"
    }
    """
    data        = request.get_json(silent=True) or {}
    auth_config = data.get("auth")

    if not auth_config:
        return jsonify({
            "success"  : False,
            "auth_type": "none",
            "detail"   : "No 'auth' key found in request body.",
        }), 400

    session, label, detail = _resolve_auth(auth_config)

    if session is None or label == "failed":
        return jsonify({
            "success"  : False,
            "auth_type": label,
            "cookies"  : {},
            "detail"   : detail,
        }), 200

    cookies     = dict(session.cookies)
    extra_check = {}

    # For DVWA: verify the session can reach an authenticated page
    if label == "dvwa_form":
        base = (auth_config.get("base_url") or "").rstrip("/")
        if base:
            try:
                resp = session.get(
                    f"{base}/index.php",
                    timeout=8, allow_redirects=True, verify=False,
                )
                body_l    = resp.text.lower()
                auth_page = "logout" in body_l or "welcome" in body_l
                extra_check["index_status"]      = resp.status_code
                extra_check["index_url"]         = resp.url
                extra_check["authenticated_page"] = auth_page

                if not auth_page:
                    return jsonify({
                        "success"  : False,
                        "auth_type": label,
                        "cookies"  : cookies,
                        "detail"   : (
                            "Session cookie was obtained but DVWA is still showing "
                            "the login/setup page. Wait ~30 s for DVWA to fully start, "
                            "then test again."
                        ),
                        **extra_check,
                    }), 200
            except Exception as exc:
                extra_check["verify_error"] = str(exc)

    return jsonify({
        "success"  : True,
        "auth_type": label,
        "cookies"  : cookies,
        "detail"   : f"Authentication succeeded — {label}",
        **extra_check,
    }), 200


# ── Discovery ─────────────────────────────────────────────────

@app.route("/api/scan/crawl", methods=["POST"])
def crawl():
    data = request.get_json(silent=True) or {}

    target_url = data.get("target_url", "").strip()
    url, err   = _validate_url(target_url)
    if err:
        return err

    max_depth   = int(data.get("max_depth", 3))
    max_urls    = int(data.get("max_urls",  100))
    auth_config = data.get("auth")

    auth_session, auth_type_label, _ = _resolve_auth(auth_config)

    try:
        crawler = Crawler(max_depth=max_depth, max_urls=max_urls, session=auth_session)
        result  = crawler.crawl(url)
        result["auth_type"] = auth_type_label
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("Crawl error")
        return jsonify({"error": str(exc)}), 500


# ── Injection ─────────────────────────────────────────────────

@app.route("/api/scan/payload", methods=["POST"])
def payload():
    data = request.get_json(silent=True) or {}

    target_url = data.get("target_url", "").strip()
    url, err   = _validate_url(target_url)
    if err:
        return err

    payload_type = data.get("payload_type", "both")
    max_payloads = int(data.get("max_payloads", 20))
    auth_config  = data.get("auth")

    if payload_type not in ("sqli", "xss", "both"):
        return jsonify({"error": "payload_type must be sqli, xss, or both"}), 400

    auth_session, auth_type_label, _ = _resolve_auth(auth_config)

    try:
        engine = PayloadEngine(
            payload_type = payload_type,
            max_payloads = max_payloads,
            session      = auth_session,
        )
        result = engine.inject(url)
        result["auth_type"] = auth_type_label
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("Payload engine error")
        return jsonify({"error": str(exc)}), 500


# ── Full scan ─────────────────────────────────────────────────

@app.route("/api/scan/full", methods=["POST"])
def full_scan():
    data = request.get_json(silent=True) or {}

    target_url = data.get("target_url", "").strip()
    url, err   = _validate_url(target_url)
    if err:
        return err

    options = {
        "max_depth"   : int(data.get("max_depth",    2)),
        "max_urls"    : int(data.get("max_urls",     40)),
        "max_targets" : int(data.get("max_targets",  10)),
        "max_payloads": int(data.get("max_payloads", 20)),
        "payload_type": data.get("payload_type", "both"),
        "auth"        : data.get("auth"),
    }

    try:
        controller = ScannerController(report_dir=REPORTS_DIR)
        result     = controller.run_scan(url, options)

        if "error" in result:
            return jsonify(result), 500

        scan_id = result["scan_id"]
        _scan_registry[scan_id] = result

        response = {
            "scan_id"         : scan_id,
            "target_url"      : result["target_url"],
            "scan_date"       : result["scan_date"],
            "duration"        : result["duration"],
            "auth_type"       : result.get("auth_type", "none"),
            "crawl_summary"   : {
                "total_visited": result["crawl_result"]["total_visited"],
                "total_failed" : result["crawl_result"]["total_failed"],
                "total_forms"  : result["crawl_result"].get("total_forms", 0),
                "base_domain"  : result["crawl_result"]["base_domain"],
            },
            "analysis"        : result["analysis"],
            "report_available": {
                "html": result.get("report_html_path") is not None,
                "pdf" : result.get("report_pdf_path")  is not None,
            },
            "report_urls"     : {
                "html": f"/api/report/{scan_id}/html",
                "pdf" : f"/api/report/{scan_id}/pdf",
            },
        }
        return jsonify(response), 200

    except Exception as exc:
        logger.exception("Full scan error")
        return jsonify({"error": str(exc)}), 500


# ── Report download ───────────────────────────────────────────

@app.route("/api/report/<scan_id>/html", methods=["GET"])
def download_html_report(scan_id: str):
    entry = _scan_registry.get(scan_id)
    if not entry:
        abort(404, description=f"No scan found with id '{scan_id}'")
    path = entry.get("report_html_path")
    if not path or not os.path.isfile(path):
        abort(404, description="HTML report not available")
    return send_file(path, mimetype="text/html", as_attachment=True,
                     download_name=f"aegis-report-{scan_id}.html")


@app.route("/api/report/<scan_id>/pdf", methods=["GET"])
def download_pdf_report(scan_id: str):
    entry = _scan_registry.get(scan_id)
    if not entry:
        abort(404, description=f"No scan found with id '{scan_id}'")
    path = entry.get("report_pdf_path")
    if not path or not os.path.isfile(path):
        return jsonify({"error": "PDF not available. pip install reportlab"}), 404
    return send_file(path, mimetype="application/pdf", as_attachment=True,
                     download_name=f"aegis-report-{scan_id}.pdf")


@app.route("/api/report/<scan_id>/summary", methods=["GET"])
def report_summary(scan_id: str):
    entry = _scan_registry.get(scan_id)
    if not entry:
        abort(404, description=f"No scan found with id '{scan_id}'")
    analysis = entry.get("analysis", {})
    return jsonify({
        "scan_id"       : scan_id,
        "target_url"    : entry["target_url"],
        "scan_date"     : entry["scan_date"],
        "auth_type"     : entry.get("auth_type", "none"),
        "overall_risk"  : analysis.get("overall_risk"),
        "total_findings": analysis.get("total_findings"),
        "critical_count": analysis.get("critical_count"),
        "high_count"    : analysis.get("high_count"),
        "medium_count"  : analysis.get("medium_count"),
        "low_count"     : analysis.get("low_count"),
    }), 200


# ── Error handlers ────────────────────────────────────────────

@app.errorhandler(404)
def not_found(exc):
    return jsonify({"error": str(exc)}), 404


@app.errorhandler(500)
def server_error(exc):
    return jsonify({"error": "Internal server error"}), 500


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)