"""
swagger.py — OpenAPI 3.0 specification for Aegis Security Platform
"""

SWAGGER_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "Aegis Security Platform API",
        "version": "1.0.0",
        "description": (
            "REST API for the Aegis automated web application security scanner. "
            "Exposes endpoints for surface discovery, injection testing, "
            "full pipeline scans, and report download.\n\n"
            "**⚠ Authorised use only.** Only scan applications you own or have "
            "explicit written permission to test."
        ),
        "contact": {"email": "security@aegis.io"},
        "license": {"name": "MIT"},
    },
    "servers": [{"url": "http://127.0.0.1:5000", "description": "Local development server"}],
    "tags": [
        {"name": "health",    "description": "Service health check"},
        {"name": "discovery", "description": "Web crawler / surface discovery"},
        {"name": "injection", "description": "Payload injection assessment"},
        {"name": "full-scan", "description": "Full four-stage pipeline"},
        {"name": "reports",   "description": "Download scan reports"},
    ],
    "paths": {
        "/api/health": {
            "get": {
                "tags": ["health"],
                "summary": "Health check",
                "description": "Returns service status and available modules.",
                "operationId": "getHealth",
                "responses": {
                    "200": {
                        "description": "Service is healthy",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/HealthResponse"},
                                "example": {
                                    "status": "ok",
                                    "service": "Aegis Security Platform",
                                    "modules": ["discovery", "injection", "analysis", "reporting"],
                                },
                            }
                        },
                    }
                },
            }
        },
        "/api/scan/crawl": {
            "post": {
                "tags": ["discovery"],
                "summary": "Surface discovery (crawler only)",
                "description": (
                    "Runs the BFS web crawler from the supplied seed URL and returns "
                    "all discovered internal pages. Does **not** perform any injection testing."
                ),
                "operationId": "runCrawl",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/CrawlRequest"},
                            "example": {
                                "target_url": "http://localhost:3000",
                                "max_depth": 2,
                                "max_urls": 40,
                            },
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Crawl completed successfully",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CrawlResponse"}
                            }
                        },
                    },
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "500": {"$ref": "#/components/responses/ServerError"},
                },
            }
        },
        "/api/scan/payload": {
            "post": {
                "tags": ["injection"],
                "summary": "Injection assessment (single URL)",
                "description": (
                    "Injects SQLi and/or XSS payloads into the first GET parameter "
                    "found in the target URL. The URL **must** include at least one "
                    "query parameter (e.g. `?id=1`); if none is present a synthetic "
                    "`input` parameter is appended automatically."
                ),
                "operationId": "runPayload",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/PayloadRequest"},
                            "example": {
                                "target_url": "http://localhost:3000/rest/products/search?q=test",
                                "payload_type": "both",
                                "max_payloads": 20,
                            },
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Assessment completed",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/PayloadResponse"}
                            }
                        },
                    },
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "500": {"$ref": "#/components/responses/ServerError"},
                },
            }
        },
        "/api/scan/full": {
            "post": {
                "tags": ["full-scan"],
                "summary": "Full pipeline scan",
                "description": (
                    "Runs the complete four-stage pipeline:\n\n"
                    "1. **Crawl** — BFS discovery of all internal pages\n"
                    "2. **Target selection** — prioritise URLs with query parameters\n"
                    "3. **Injection testing** — SQLi + XSS against each target\n"
                    "4. **Analysis & reporting** — severity scoring + HTML/PDF report\n\n"
                    "Returns a `scan_id` that can be used to download the report. "
                    "Scans may take several minutes depending on site size."
                ),
                "operationId": "runFullScan",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/FullScanRequest"},
                            "example": {
                                "target_url": "http://localhost:3000",
                                "max_depth": 2,
                                "max_urls": 40,
                                "max_targets": 10,
                                "max_payloads": 20,
                                "payload_type": "both",
                            },
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Full scan completed",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/FullScanResponse"}
                            }
                        },
                    },
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "500": {"$ref": "#/components/responses/ServerError"},
                },
            }
        },
        "/api/report/{scan_id}/html": {
            "get": {
                "tags": ["reports"],
                "summary": "Download HTML report",
                "operationId": "downloadHtml",
                "parameters": [{"$ref": "#/components/parameters/ScanId"}],
                "responses": {
                    "200": {
                        "description": "Standalone HTML report file",
                        "content": {"text/html": {"schema": {"type": "string", "format": "binary"}}},
                    },
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            }
        },
        "/api/report/{scan_id}/pdf": {
            "get": {
                "tags": ["reports"],
                "summary": "Download PDF report",
                "description": "Requires `reportlab` to be installed (`pip install reportlab`).",
                "operationId": "downloadPdf",
                "parameters": [{"$ref": "#/components/parameters/ScanId"}],
                "responses": {
                    "200": {
                        "description": "PDF report file",
                        "content": {"application/pdf": {"schema": {"type": "string", "format": "binary"}}},
                    },
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            }
        },
        "/api/report/{scan_id}/summary": {
            "get": {
                "tags": ["reports"],
                "summary": "JSON scan summary",
                "operationId": "getSummary",
                "parameters": [{"$ref": "#/components/parameters/ScanId"}],
                "responses": {
                    "200": {
                        "description": "Summary of a completed scan",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanSummary"}
                            }
                        },
                    },
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            }
        },
    },
    "components": {
        "parameters": {
            "ScanId": {
                "name": "scan_id",
                "in": "path",
                "required": True,
                "description": "8-character scan identifier returned by `/api/scan/full`",
                "schema": {"type": "string", "example": "a1b2c3d4"},
            }
        },
        "responses": {
            "BadRequest": {
                "description": "Invalid request body",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                    }
                },
            },
            "NotFound": {
                "description": "Scan or report not found",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                    }
                },
            },
            "ServerError": {
                "description": "Internal server error",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                    }
                },
            },
        },
        "schemas": {
            "HealthResponse": {
                "type": "object",
                "properties": {
                    "status":  {"type": "string", "example": "ok"},
                    "service": {"type": "string", "example": "Aegis Security Platform"},
                    "modules": {"type": "array", "items": {"type": "string"}},
                },
            },
            "CrawlRequest": {
                "type": "object",
                "required": ["target_url"],
                "properties": {
                    "target_url": {"type": "string", "format": "uri", "description": "Seed URL to crawl"},
                    "max_depth":  {"type": "integer", "default": 3, "minimum": 1, "maximum": 10},
                    "max_urls":   {"type": "integer", "default": 100, "minimum": 5, "maximum": 500},
                },
            },
            "CrawlResponse": {
                "type": "object",
                "properties": {
                    "seed_url":      {"type": "string"},
                    "base_domain":   {"type": "string"},
                    "visited_urls":  {"type": "array", "items": {"type": "string"}},
                    "failed_urls":   {"type": "array", "items": {"type": "string"}},
                    "total_visited": {"type": "integer"},
                    "total_failed":  {"type": "integer"},
                    "crawl_depth":   {"type": "integer"},
                },
            },
            "PayloadRequest": {
                "type": "object",
                "required": ["target_url"],
                "properties": {
                    "target_url":   {"type": "string", "format": "uri"},
                    "payload_type": {
                        "type": "string",
                        "enum": ["sqli", "xss", "both"],
                        "default": "both",
                    },
                    "max_payloads": {"type": "integer", "default": 20, "minimum": 1, "maximum": 100},
                },
            },
            "PayloadResponse": {
                "type": "object",
                "properties": {
                    "target_url":       {"type": "string"},
                    "params_found":     {"type": "array", "items": {"type": "string"}},
                    "total_tested":     {"type": "integer"},
                    "total_vulnerable": {"type": "integer"},
                    "total_clean":      {"type": "integer"},
                    "total_errors":     {"type": "integer"},
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "url":         {"type": "string"},
                                "param":       {"type": "string"},
                                "payload":     {"type": "string"},
                                "type":        {"type": "string", "enum": ["sqli", "xss"]},
                                "status":      {"type": "string", "enum": ["clean", "vulnerable", "error"]},
                                "status_code": {"type": "integer"},
                                "evidence":    {"type": "string"},
                            },
                        },
                    },
                },
            },
            "FullScanRequest": {
                "type": "object",
                "required": ["target_url"],
                "properties": {
                    "target_url":   {"type": "string", "format": "uri"},
                    "max_depth":    {"type": "integer", "default": 2, "minimum": 1, "maximum": 5},
                    "max_urls":     {"type": "integer", "default": 40, "minimum": 5, "maximum": 200},
                    "max_targets":  {"type": "integer", "default": 10, "minimum": 1, "maximum": 50},
                    "max_payloads": {"type": "integer", "default": 20, "minimum": 1, "maximum": 100},
                    "payload_type": {
                        "type": "string",
                        "enum": ["sqli", "xss", "both"],
                        "default": "both",
                    },
                },
            },
            "FullScanResponse": {
                "type": "object",
                "properties": {
                    "scan_id":    {"type": "string", "example": "a1b2c3d4"},
                    "target_url": {"type": "string"},
                    "scan_date":  {"type": "string"},
                    "duration":   {"type": "string"},
                    "crawl_summary": {
                        "type": "object",
                        "properties": {
                            "total_visited": {"type": "integer"},
                            "total_failed":  {"type": "integer"},
                            "base_domain":   {"type": "string"},
                        },
                    },
                    "analysis": {
                        "type": "object",
                        "properties": {
                            "total_findings": {"type": "integer"},
                            "critical_count": {"type": "integer"},
                            "high_count":     {"type": "integer"},
                            "medium_count":   {"type": "integer"},
                            "low_count":      {"type": "integer"},
                            "overall_risk":   {"type": "string", "enum": ["Critical","High","Medium","Low","Clean"]},
                        },
                    },
                    "report_urls": {
                        "type": "object",
                        "properties": {
                            "html": {"type": "string"},
                            "pdf":  {"type": "string"},
                        },
                    },
                },
            },
            "ScanSummary": {
                "type": "object",
                "properties": {
                    "scan_id":        {"type": "string"},
                    "target_url":     {"type": "string"},
                    "scan_date":      {"type": "string"},
                    "overall_risk":   {"type": "string"},
                    "total_findings": {"type": "integer"},
                    "critical_count": {"type": "integer"},
                    "high_count":     {"type": "integer"},
                    "medium_count":   {"type": "integer"},
                    "low_count":      {"type": "integer"},
                },
            },
            "ErrorResponse": {
                "type": "object",
                "properties": {
                    "error": {"type": "string"}
                },
            },
        },
    },
}