"""
app.py — Aegis Security Backend
=================================
Flask REST API server.

Routes
------
GET  /api/health        — health check
POST /api/scan/crawl    — surface discovery
POST /api/scan/payload  — injection assessment
"""

from flask import Flask, request, jsonify
from flask_cors import CORS

from scanner.crawler        import Crawler
from scanner.payload_engine import PayloadEngine

app = Flask(__name__)
CORS(app)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status":  "ok",
        "service": "Aegis Security Platform",
        "modules": ["discovery", "injection"]
    }), 200


@app.route("/api/scan/crawl", methods=["POST"])
def crawl():
    data = request.get_json(silent=True)
    if not data or "target_url" not in data:
        return jsonify({"error": "Missing required field: target_url"}), 400

    target_url = data["target_url"].strip()
    max_depth  = int(data.get("max_depth", 3))
    max_urls   = int(data.get("max_urls",  100))

    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "target_url must start with http:// or https://"}), 400

    crawler = Crawler(max_depth=max_depth, max_urls=max_urls)
    result  = crawler.crawl(target_url)
    return jsonify(result), 200


@app.route("/api/scan/payload", methods=["POST"])
def payload():
    data = request.get_json(silent=True)
    if not data or "target_url" not in data:
        return jsonify({"error": "Missing required field: target_url"}), 400

    target_url   = data["target_url"].strip()
    payload_type = data.get("payload_type", "both")
    max_payloads = int(data.get("max_payloads", 20))

    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "target_url must start with http:// or https://"}), 400

    if payload_type not in ("sqli", "xss", "both"):
        return jsonify({"error": "payload_type must be sqli, xss, or both"}), 400

    engine = PayloadEngine(payload_type=payload_type, max_payloads=max_payloads)
    result = engine.inject(target_url)
    return jsonify(result), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)