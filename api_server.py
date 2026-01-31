"""
Synchronous DAST Engine API Server (Improved)
- Thread-safe + low lock contention
- Background scan threads
- Polling endpoints for frontend
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from threading import Thread, Lock
import json
import uuid
import time
from datetime import datetime
import os
import sys
from queue import Queue, Full
import logging
from urllib.parse import urlparse

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.engine import DASTEngine

app = Flask(__name__)
CORS(app)

# ============ CONFIG / LIMITS ============

MAX_CONCURRENT_SCANS = 5
MAX_PAGES_LIMIT = 200

# Reduce event spam
CRAWL_PROGRESS_EVERY_N = 5
SCAN_PROGRESS_EVERY_N = 2

INTERNAL_IP_PREFIXES = (
    "127.",
    "10.",
    "192.168.",
    "169.254.",
    "::1",
)

REPORTS_DIR = "dast_report"
os.makedirs(REPORTS_DIR, exist_ok=True)


def is_url_allowed(target_url: str) -> bool:
    """Basic SSRF safety: only http/https, block common internal ranges by default."""
    try:
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname or ""
        if host in ("localhost",):
            return False
        for prefix in INTERNAL_IP_PREFIXES:
            if host.startswith(prefix):
                return False
        return True
    except Exception:
        return False


# ============ GLOBAL STORAGE ============

scans_db = {}
scan_events_db = {}
db_lock = Lock()

active_scans = {}
events_queue = Queue(maxsize=2000)  # prevent unbounded growth


# ============ EVENT SYSTEM (SYNC) ============

def add_event(scan_id: str, event_type: str, data: dict, message: str = None):
    """
    Add event to database (thread-safe) but keep lock hold minimal.
    Heavy I/O (logging/queue) is outside the lock to avoid blocking status endpoints. [web:291][web:292]
    """
    event = {
        "event_type": event_type,
        "timestamp": datetime.now().isoformat(),
        "scan_id": scan_id,
        "data": data,
    }
    if message:
        event["message"] = message

    # Only mutate shared structures under lock
    with db_lock:
        if scan_id not in scan_events_db:
            scan_events_db[scan_id] = []
        scan_events_db[scan_id].append(event)

        # Keep only last 100 events
        if len(scan_events_db[scan_id]) > 100:
            scan_events_db[scan_id] = scan_events_db[scan_id][-100:]

    # Outside lock: non-blocking queue + logging
    try:
        events_queue.put_nowait((scan_id, event))
    except Full:
        pass

    logger.info(f"Event: {scan_id} - {event_type}: {message or ''}")
    return event


# ============ SYNCHRONOUS SCAN RUNNER ============

class SyncScanRunner:
    """Synchronous scan runner with event emission"""

    def __init__(self, scan_id: str, target_url: str, scan_type: str, max_pages: int, config: dict):
        self.scan_id = scan_id
        self.target_url = target_url
        self.scan_type = scan_type
        self.max_pages = max_pages
        self.config = config
        self.engine = None
        self.crawled_pages = []
        self.vulnerabilities = []

    def _is_cancelled(self) -> bool:
        with db_lock:
            return scans_db.get(self.scan_id, {}).get("status") == "cancelled"

    def _set_status(self, status: str, progress: int = None, error: str = None):
        with db_lock:
            if self.scan_id not in scans_db:
                return
            scans_db[self.scan_id]["status"] = status
            if progress is not None:
                scans_db[self.scan_id]["progress"] = int(progress)
            if error is not None:
                scans_db[self.scan_id]["error"] = error
            if status in ("completed", "failed", "cancelled"):
                scans_db[self.scan_id]["completed_at"] = datetime.now().isoformat()

    def run(self):
        try:
            add_event(
                self.scan_id,
                "scan_started",
                {"target_url": self.target_url, "scan_type": self.scan_type, "max_pages": self.max_pages},
                f"Starting scan of {self.target_url}",
            )

            self._set_status("initializing", progress=5)
            add_event(self.scan_id, "progress", {"progress": 5, "step": "initializing", "message": "Setting up DAST engine"})

            add_event(self.scan_id, "progress", {"progress": 10, "step": "engine_init", "message": "Initializing scanners and crawlers"})

            engine_config = {
                "max_pages": self.max_pages,
                "timeout": 30,
                "user_agent": "DAST-Scanner/API",
                **(self.config or {}),
            }

            self.engine = DASTEngine(config=engine_config)

            self._set_status("crawling", progress=15)
            add_event(self.scan_id, "progress", {"progress": 15, "step": "crawling_start", "message": f"Starting to crawl {self.target_url}"})
            logger.info(f"Starting crawl for {self.target_url}")

            # STEP 2: Crawling
            try:
                self.crawled_pages = self.engine.smart_crawler.smart_crawl(self.target_url, max_pages=self.max_pages) or []
            except Exception as e:
                add_event(self.scan_id, "error", {"error": str(e), "step": "crawling"}, f"Crawling error: {e}")
                logger.error(f"Crawling error: {e}")
                self._set_status("failed", error=f"Crawling failed: {e}")
                return

            total_crawled = len(self.crawled_pages)
            for i, page in enumerate(self.crawled_pages):
                if self._is_cancelled():
                    logger.info(f"Scan {self.scan_id} cancelled during crawl")
                    return

                page_url = (page or {}).get("url", "")

                # Emit crawler event (ok), but don't spam progress every URL
                add_event(
                    self.scan_id,
                    "crawler",
                    {"url": page_url, "status": "discovered", "details": {"page_number": i + 1, "total_pages": total_crawled}},
                    f"Discovered URL: {page_url}",
                )

                # progress update throttled
                if i == 0 or (i + 1) % CRAWL_PROGRESS_EVERY_N == 0 or (i + 1) == total_crawled:
                    progress = 15 + (i / max(total_crawled, 1) * 25)
                    self._set_status("crawling", progress=int(progress))
                    add_event(
                        self.scan_id,
                        "progress",
                        {"progress": int(progress), "step": "crawling", "message": f"Crawled {i+1}/{total_crawled} pages"},
                    )

                time.sleep(0.02)

            #discover urls
            discovered_urls = []
            seen = set()
            for p in (self.crawled_pages or []):
              u = (p or {}).get("url")
              if u and u not in seen:
                seen.add(u)
                discovered_urls.append(u)

            

            # STEP 3: Vulnerability Scanning
            self._set_status("scanning", progress=40)
            add_event(self.scan_id, "progress", {"progress": 40, "step": "scanning_start", "message": "Starting vulnerability scanning"})

            total_pages = len(self.crawled_pages)
            for page_idx, page in enumerate(self.crawled_pages):
                if self._is_cancelled():
                    logger.info(f"Scan {self.scan_id} cancelled during scanning")
                    return

                page_url = (page or {}).get("url", "")

                # throttled progress
                if page_idx == 0 or (page_idx + 1) % SCAN_PROGRESS_EVERY_N == 0 or (page_idx + 1) == total_pages:
                    page_progress = 40 + (page_idx / max(total_pages, 1) * 50)
                    self._set_status("scanning", progress=int(page_progress))
                    add_event(
                        self.scan_id,
                        "progress",
                        {"progress": int(page_progress), "step": "scanning", "message": f"Scanning {page_idx+1}/{total_pages}: {page_url[:60]}"},
                    )

                for scanner_name, scanner in (self.engine.scanners or {}).items():
                    if self._is_cancelled():
                        logger.info(f"Scan {self.scan_id} cancelled mid-scanner loop")
                        return
                    if not scanner:
                        continue

                    try:
                        add_event(
                            self.scan_id,
                            "scanner",
                            {"scanner": scanner_name, "url": page_url, "status": "started", "vulnerabilities_found": 0},
                            f"Scanner {scanner_name} started on {page_url}",
                        )

                        results = scanner.scan_url(page_url) or []  # important: avoid None -> len(None) crash

                        for vuln in results:
                            raw_sev = vuln.get("severity") or vuln.get("risk") or "medium"
                            sev_norm = str(raw_sev).lower()
                            if sev_norm not in ("critical", "high", "medium", "low", "info"):
                                sev_norm = "medium"

                            vuln["severity"] = sev_norm
                            vuln["scan_id"] = self.scan_id
                            vuln["detected_at"] = datetime.now().isoformat()
                            self.vulnerabilities.append(vuln)

                            add_event(
                                self.scan_id,
                                "vulnerability_found",
                                {"vulnerability": vuln},
                                f"Found {vuln.get('type')} vulnerability",
                            )

                        add_event(
                            self.scan_id,
                            "scanner",
                            {"scanner": scanner_name, "url": page_url, "status": "completed", "vulnerabilities_found": len(results)},
                            f"Scanner {scanner_name} completed",
                        )

                    except Exception as e:
                        add_event(
                            self.scan_id,
                            "scanner_error",
                            {"scanner": scanner_name, "error": str(e), "url": page_url},
                            f"Scanner {scanner_name} error: {e}",
                        )
                        logger.error(f"Scanner {scanner_name} error: {e}")

            # STEP 4: Results Processing
            if self._is_cancelled():
                logger.info(f"Scan {self.scan_id} cancelled before processing")
                return

            self._set_status("processing", progress=90)
            add_event(self.scan_id, "progress", {"progress": 90, "step": "processing", "message": "Generating scan report"})

            with db_lock:
                started_at = scans_db[self.scan_id]["started_at"]

            report = {
                "scan_id": self.scan_id,
                "target_url": self.target_url,
                "scan_type": self.scan_type,
                "start_time": started_at,
                "end_time": datetime.now().isoformat(),
                "discovered_urls": discovered_urls, 
                "summary": {
                    "total_pages": len(discovered_urls),
                    "total_pages": len(self.crawled_pages),
                    "total_vulnerabilities": len(self.vulnerabilities),
                    "by_type": {},
                    "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                },
                "vulnerabilities": self.vulnerabilities,
            }

            for vuln in self.vulnerabilities:
                vtype = vuln.get("type", "unknown")
                severity = (vuln.get("severity") or "medium").lower()

                report["summary"]["by_type"][vtype] = report["summary"]["by_type"].get(vtype, 0) + 1
                if severity in report["summary"]["by_severity"]:
                    report["summary"]["by_severity"][severity] += 1

            filename = f"scan_{self.scan_id}.json"
            filepath = os.path.join(REPORTS_DIR, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            with db_lock:
                scans_db[self.scan_id]["results"] = report
                scans_db[self.scan_id]["report_file"] = filepath

            self._set_status("completed", progress=100)

            add_event(self.scan_id, "progress", {"progress": 100, "step": "completed", "message": f"Scan completed! Found {len(self.vulnerabilities)} vulnerabilities"})
            add_event(self.scan_id, "scan_completed", report["summary"], f"Scan completed with {len(self.vulnerabilities)} vulnerabilities")

            logger.info(f"✅ Scan {self.scan_id} completed successfully")

        except Exception as e:
            self._set_status("failed", error=str(e))
            add_event(self.scan_id, "scan_failed", {"error": str(e)}, f"❌ Scan failed: {str(e)}")
            logger.error(f"❌ Scan {self.scan_id} failed: {e}")

        finally:
            with db_lock:
                if self.scan_id in active_scans:
                    del active_scans[self.scan_id]


def run_scan_in_thread(scan_id: str, target_url: str, scan_type: str, max_pages: int, config: dict):
    runner = SyncScanRunner(scan_id, target_url, scan_type, max_pages, config)
    runner.run()


# ============ FLASK ROUTES ============

@app.route("/")
def root():
    return jsonify({
        "service": "DAST Engine API (Synchronous)",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health [GET]",
            "start_scan": "/scan/start [POST]",
            "scan_status": "/scan/<id>/status [GET]",
            "scan_events": "/scan/<id>/events [GET]",
            "scan_results": "/scan/<id>/results [GET]",
            "download_report": "/scan/<id>/report [GET]",
            "list_scans": "/scans [GET]",
        },
        "note": "This is a synchronous API compatible with Playwright",
    })


@app.route("/health", methods=["GET"])
def health():
    with db_lock:
        active_count = len(active_scans)
        total_count = len(scans_db)

    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_scans": active_count,
        "total_scans": total_count,
    })


@app.route("/scan/start", methods=["POST"])
def start_scan():
    """Start a new scan"""
    try:
        data = request.get_json(silent=True) or {}

        target_url = data.get("target_url")
        if not target_url or not isinstance(target_url, str):
            return jsonify({"success": False, "error": "target_url (string) is required"}), 400

        if not is_url_allowed(target_url):
            return jsonify({"success": False, "error": "target_url is not allowed (only http/https, no localhost/internal by default)"}), 400

        max_pages = data.get("max_pages", 10)
        try:
            max_pages = int(max_pages)
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "max_pages must be an integer"}), 400

        max_pages = max(1, min(max_pages, MAX_PAGES_LIMIT))
        scan_type = data.get("scan_type", "quick")

        config = data.get("config", {})
        if not isinstance(config, dict):
            config = {}

        with db_lock:
            running = sum(
                1 for s in scans_db.values()
                if s.get("status") in ("queued", "initializing", "crawling", "scanning")
            )

        if running >= MAX_CONCURRENT_SCANS:
            return jsonify({"success": False, "error": "Too many scans running, please try again later"}), 429

        scan_id = str(uuid.uuid4())[:8]

        with db_lock:
            scans_db[scan_id] = {
                "scan_id": scan_id,
                "target_url": target_url,
                "scan_type": scan_type,
                "max_pages": max_pages,
                "config": config,
                "status": "queued",
                "progress": 0,
                "started_at": datetime.now().isoformat(),
                "completed_at": None,
                "results": None,
                "report_file": None,
                "error": None,
            }

        thread = Thread(target=run_scan_in_thread, args=(scan_id, target_url, scan_type, max_pages, config), daemon=True)

        with db_lock:
            active_scans[scan_id] = thread

        thread.start()

        add_event(scan_id, "scan_queued", {"target_url": target_url}, "Scan queued for execution")

        base_url = request.host_url.rstrip("/")
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "message": "Scan started successfully",
            "endpoints": {
                "status": f"{base_url}/scan/{scan_id}/status",
                "events": f"{base_url}/scan/{scan_id}/events",
                "results": f"{base_url}/scan/{scan_id}/results",
                "poll": f"{base_url}/scan/{scan_id}/poll",
            },
        }), 202

    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/scan/<scan_id>/status", methods=["GET"])
def get_scan_status(scan_id):
    # snapshot under lock, respond outside lock
    with db_lock:
        scan_data = scans_db.get(scan_id)
        if not scan_data:
            return jsonify({"success": False, "error": "Scan not found"}), 404
        scan_snapshot = dict(scan_data)

    response = {
        "success": True,
        "scan_id": scan_id,
        "target_url": scan_snapshot["target_url"],
        "status": scan_snapshot["status"],
        "progress": scan_snapshot["progress"],
        "started_at": scan_snapshot["started_at"],
        "completed_at": scan_snapshot.get("completed_at"),
        "scan_type": scan_snapshot.get("scan_type", "quick"),
    }

    results = scan_snapshot.get("results")
    if results:
        response["summary"] = results.get("summary", {})
        response["vulnerabilities_count"] = len(results.get("vulnerabilities", []))

    return jsonify(response)


@app.route("/scan/<scan_id>/events", methods=["GET"])
def get_scan_events(scan_id):
    limit = request.args.get("limit", 50, type=int)

    with db_lock:
        events_list = scan_events_db.get(scan_id)
        if not events_list:
            return jsonify({"success": False, "error": "No events found for this scan"}), 404
        # snapshot
        events = list(events_list[-limit:])

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "total_events": len(events_list),
        "events": events,
    })


@app.route("/scan/<scan_id>/poll", methods=["GET"])
def poll_scan_updates(scan_id):
    since = request.args.get("since", 0, type=int)

    with db_lock:
        all_events = scan_events_db.get(scan_id)
        if not all_events:
            return jsonify({"success": False, "error": "No events found"}), 404
        new_events = list(all_events[since:])

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "events": new_events,
        "next_poll": since + len(new_events),
        "has_more": len(new_events) > 0,
    })


@app.route("/scan/<scan_id>/results", methods=["GET"])
def get_scan_results(scan_id):
    with db_lock:
        scan_data = scans_db.get(scan_id)
        if not scan_data:
            return jsonify({"success": False, "error": "Scan not found"}), 404
        status = scan_data.get("status")
        results = scan_data.get("results")

    if status != "completed":
        return jsonify({"success": False, "error": "Scan not completed yet", "status": status}), 400
    if not results:
        return jsonify({"success": False, "error": "Results not found"}), 404

    return jsonify({"success": True, "scan_id": scan_id, **results})


@app.route("/scan/<scan_id>/report", methods=["GET"])
def download_report(scan_id):
    with db_lock:
        scan_data = scans_db.get(scan_id)
        if not scan_data:
            return jsonify({"success": False, "error": "Scan not found"}), 404
        filepath = scan_data.get("report_file")

    if not filepath:
        return jsonify({"success": False, "error": "Report not found"}), 404

    return send_file(
        filepath,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"dast_scan_{scan_id}.json",
    )


@app.route("/scans", methods=["GET"])
def list_scans():
    with db_lock:
        items = list(scans_db.items())

    scans_list = []
    for scan_id, data in items:
        results = data.get("results") or {}
        scans_list.append({
            "scan_id": scan_id,
            "target_url": data.get("target_url"),
            "status": data.get("status"),
            "progress": data.get("progress"),
            "started_at": data.get("started_at"),
            "completed_at": data.get("completed_at"),
            "vulnerabilities_count": len(results.get("vulnerabilities", [])) if results else 0,
        })

    scans_list.sort(key=lambda x: x.get("started_at", ""), reverse=True)

    return jsonify({"success": True, "total_scans": len(scans_list), "scans": scans_list})


@app.route("/scan/<scan_id>/cancel", methods=["POST"])
def cancel_scan(scan_id):
    with db_lock:
        scan_data = scans_db.get(scan_id)
        if not scan_data:
            return jsonify({"success": False, "error": "Scan not found"}), 404

        if scan_data.get("status") not in ("queued", "initializing", "crawling", "scanning"):
            return jsonify({"success": False, "error": "Scan cannot be cancelled in current state"}), 400

        scans_db[scan_id]["status"] = "cancelled"
        scans_db[scan_id]["completed_at"] = datetime.now().isoformat()

    add_event(scan_id, "scan_cancelled", {}, "Scan cancelled by user")
    return jsonify({"success": True, "message": "Scan cancelled successfully"})


if __name__ == "__main__":
    logger.info("🚀 Starting Synchronous DAST Engine API Server...")
    logger.info("📡 REST API: http://localhost:8001")
    logger.info("⚡ Using synchronous mode (compatible with Playwright)")

    app.run(
        host="0.0.0.0",
        port=8001,
        debug=False,
        threaded=True,
    )
