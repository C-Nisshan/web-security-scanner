"""
app.py — Aegis Security Backend
=================================
Flask REST API server.

Routes
------
GET  /api/health                — health-check
POST /api/scan/crawl            — surface discovery only
POST /api/scan/payload          — injection assessment only
POST /api/scan/full             — full pipeline (crawl → inject → analyse → report)
GET  /api/report/<id>/html      — download HTML report
GET  /api/report/<id>/pdf       — download PDF report
GET  /api/report/<id>/summary   — JSON summary of a completed scan
"""

import os
import logging
from flask          import Flask, request, jsonify, send_file, abort
from flask_cors     import CORS

from scanner.crawler          import Crawler
from scanner.payload_engine   import PayloadEngine
from scanner.controller       import ScannerController

# ── App setup ────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [APP]  %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("app")

app = Flask(__name__)
CORS(app)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# In-memory scan registry  { scan_id: result_dict }
_scan_registry: dict = {}


# ── Helpers ──────────────────────────────────────────────────

def _validate_url(url: str):
    """Return (url, error_response) tuple."""
    if not url:
        return None, jsonify({"error": "Missing required field: target_url"}), 400
    if not url.startswith(("http://", "https://")):
        return None, jsonify({"error": "target_url must start with http:// or https://"}), 400
    return url, None


# ── Health check ─────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status" : "ok",
        "service": "Aegis Security Platform",
        "modules": ["discovery", "injection", "analysis", "reporting"],
    }), 200


# ── Discovery (crawler only) ─────────────────────────────────

@app.route("/api/scan/crawl", methods=["POST"])
def crawl():
    data = request.get_json(silent=True) or {}

    target_url = data.get("target_url", "").strip()
    url, err   = _validate_url(target_url)
    if err:
        return err

    max_depth = int(data.get("max_depth", 3))
    max_urls  = int(data.get("max_urls",  100))

    try:
        crawler = Crawler(max_depth=max_depth, max_urls=max_urls)
        result  = crawler.crawl(url)
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("Crawl error")
        return jsonify({"error": str(exc)}), 500


# ── Injection (payload engine only) ──────────────────────────

@app.route("/api/scan/payload", methods=["POST"])
def payload():
    data = request.get_json(silent=True) or {}

    target_url = data.get("target_url", "").strip()
    url, err   = _validate_url(target_url)
    if err:
        return err

    payload_type = data.get("payload_type", "both")
    max_payloads = int(data.get("max_payloads", 20))

    if payload_type not in ("sqli", "xss", "both"):
        return jsonify({"error": "payload_type must be sqli, xss, or both"}), 400

    try:
        engine = PayloadEngine(
            payload_type=payload_type,
            max_payloads=max_payloads,
        )
        result = engine.inject(url)
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("Payload engine error")
        return jsonify({"error": str(exc)}), 500


# ── Full scan pipeline ────────────────────────────────────────

@app.route("/api/scan/full", methods=["POST"])
def full_scan():
    """
    Runs the complete pipeline: crawl → inject → analyse → report.

    Request body (JSON)
    -------------------
    target_url   : str  (required)
    max_depth    : int  (default 2)
    max_urls     : int  (default 40)
    max_targets  : int  (default 10)  — URLs to injection-test
    max_payloads : int  (default 20)
    payload_type : str  (default "both")

    Response
    --------
    JSON containing full analysis + scan_id for report download.
    """
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
    }

    try:
        controller = ScannerController(report_dir=REPORTS_DIR)
        result     = controller.run_scan(url, options)

        if "error" in result:
            return jsonify(result), 500

        # Store for later download
        scan_id = result["scan_id"]
        _scan_registry[scan_id] = result

        # Build a clean JSON-safe response (strip file paths from public output)
        response = {
            "scan_id"         : scan_id,
            "target_url"      : result["target_url"],
            "scan_date"       : result["scan_date"],
            "duration"        : result["duration"],
            "crawl_summary"   : {
                "total_visited": result["crawl_result"]["total_visited"],
                "total_failed" : result["crawl_result"]["total_failed"],
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

    return send_file(
        path,
        mimetype="text/html",
        as_attachment=True,
        download_name=f"aegis-report-{scan_id}.html",
    )


@app.route("/api/report/<scan_id>/pdf", methods=["GET"])
def download_pdf_report(scan_id: str):
    entry = _scan_registry.get(scan_id)
    if not entry:
        abort(404, description=f"No scan found with id '{scan_id}'")

    path = entry.get("report_pdf_path")
    if not path or not os.path.isfile(path):
        return jsonify({
            "error": "PDF report not available. Ensure ReportLab is installed: "
                     "pip install reportlab"
        }), 404

    return send_file(
        path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"aegis-report-{scan_id}.pdf",
    )


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
    app.run(host="0.0.0.0", port=5000, debug=True)