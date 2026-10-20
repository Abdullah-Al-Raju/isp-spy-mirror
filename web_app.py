"""
FastAPI web application & WebSocket telemetry control center for ISP Spy Mirror.
Enables real-time traffic monitoring, dynamic privacy threat scoring,
live event streaming, and interactive privacy test scenario injection.
"""

import os
import sys
import time
import asyncio
import json
from datetime import datetime
from collections import deque
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

from capture import CaptureEngine
from reports.dossier import ISPDossier
from reports.html_report import HTMLReport
from utils.helpers import bytes_to_human, get_default_interface

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _broadcast_task
    _broadcast_task = asyncio.create_task(broadcast_loop())
    yield
    if _broadcast_task:
        _broadcast_task.cancel()

app = FastAPI(title="ISP Spy Mirror Web Dashboard", version="2.0.0", lifespan=lifespan)

# Mount web assets
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
os.makedirs(WEB_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

# Global State
global_engine: Optional[CaptureEngine] = None
recent_events = deque(maxlen=1000)
connected_clients = set()
_broadcast_task = None
_last_packet_count = 0
_last_rate_time = time.time()


class ScenarioRequest(BaseModel):
    scenario: str


class StartRequest(BaseModel):
    mode: str = "simulate"  # "simulate" or "live"
    interface: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(WEB_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h2>ISP Spy Mirror web dashboard assets missing</h2>")


@app.get("/api/status")
async def get_status():
    engine = get_active_engine()
    telemetry = build_telemetry_payload(engine)
    return {
        "status": "online",
        "running": engine.is_running() if engine else False,
        "paused": engine.is_paused() if engine else False,
        "telemetry": telemetry,
    }


@app.get("/api/stats")
async def get_stats():
    engine = get_active_engine()
    if not engine:
        raise HTTPException(status_code=503, detail="Capture engine not initialized")
    return engine.get_all_stats()


@app.get("/api/dossier")
async def get_dossier():
    engine = get_active_engine()
    if not engine:
        raise HTTPException(status_code=503, detail="Capture engine not initialized")
    stats = engine.get_all_stats()
    dossier = ISPDossier(stats)
    return dossier.dossier


@app.get("/api/events")
async def get_events(limit: int = 100):
    events_list = list(recent_events)
    return events_list[-limit:]


@app.post("/api/control/pause")
async def pause_capture():
    engine = get_active_engine()
    if engine:
        engine.pause()
        return {"status": "paused", "paused": True}
    return {"status": "error", "message": "Engine not running"}


@app.post("/api/control/resume")
async def resume_capture():
    engine = get_active_engine()
    if engine:
        engine.resume()
        return {"status": "resumed", "paused": False}
    return {"status": "error", "message": "Engine not running"}


@app.post("/api/control/inject")
async def inject_scenario(payload: ScenarioRequest):
    engine = get_active_engine()
    if not engine:
        raise HTTPException(status_code=503, detail="Engine not active")
    pkt = engine.inject_scenario(payload.scenario)
    return {"status": "injected", "scenario": payload.scenario, "packet_created": pkt is not None}


@app.get("/api/export/pcap")
async def export_pcap():
    engine = get_active_engine()
    if not engine:
        raise HTTPException(status_code=503, detail="Engine not active")
    pcap_path = engine.pcap_exporter.export(session_id=engine.session_id)
    if pcap_path and os.path.exists(pcap_path):
        return FileResponse(
            pcap_path,
            media_type="application/vnd.tcpdump.pcap",
            filename=os.path.basename(pcap_path),
        )
    raise HTTPException(status_code=404, detail="No PCAP packets recorded yet")


@app.get("/api/export/html")
async def export_html():
    engine = get_active_engine()
    if not engine:
        raise HTTPException(status_code=503, detail="Engine not active")
    stats = engine.get_all_stats()
    html_report = HTMLReport()
    report_path = html_report.generate(stats)
    if report_path and os.path.exists(report_path):
        return FileResponse(
            report_path,
            media_type="text/html",
            filename=os.path.basename(report_path),
        )
    raise HTTPException(status_code=500, detail="HTML report generation failed")


@app.get("/api/export/json")
async def export_json():
    engine = get_active_engine()
    if not engine:
        raise HTTPException(status_code=503, detail="Engine not active")
    stats = engine.get_all_stats()
    dossier = ISPDossier(stats).dossier
    return JSONResponse(content={"stats": stats, "dossier": dossier})


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)

    # Send initial telemetry snapshot and recent events
    try:
        engine = get_active_engine()
        telemetry = build_telemetry_payload(engine)
        await websocket.send_text(json.dumps({"type": "telemetry", "payload": telemetry}))

        if recent_events:
            batch = list(recent_events)[-50:]
            await websocket.send_text(json.dumps({"type": "event_batch", "payload": batch}))

        while True:
            msg_text = await websocket.receive_text()
            try:
                msg = json.loads(msg_text)
                action = msg.get("action")
                if action == "pause":
                    engine.pause()
                elif action == "resume":
                    engine.resume()
                elif action == "inject":
                    scenario = msg.get("scenario", "")
                    if scenario:
                        engine.inject_scenario(scenario)
            except Exception:
                pass

    except WebSocketDisconnect:
        pass
    finally:
        connected_clients.discard(websocket)


async def broadcast_loop():
    """Background coroutine to stream captured events and telemetry over WebSockets."""
    global _last_packet_count, _last_rate_time
    last_telemetry_time = time.time()

    while True:
        try:
            engine = get_active_engine()
            if engine:
                # Drain event queue from engine
                new_events = []
                for _ in range(30):
                    evt = engine.get_event(timeout=0.01)
                    if evt:
                        recent_events.append(evt)
                        new_events.append(evt)
                    else:
                        break

                if new_events and connected_clients:
                    payload = json.dumps({"type": "event_batch", "payload": new_events})
                    dead = []
                    for ws_client in list(connected_clients):
                        try:
                            await ws_client.send_text(payload)
                        except Exception:
                            dead.append(ws_client)
                    for d in dead:
                        connected_clients.discard(d)

                # Periodic telemetry update (every 400ms)
                now = time.time()
                if (now - last_telemetry_time) >= 0.4:
                    last_telemetry_time = now
                    telemetry = build_telemetry_payload(engine)
                    payload = json.dumps({"type": "telemetry", "payload": telemetry})
                    dead = []
                    for ws_client in list(connected_clients):
                        try:
                            await ws_client.send_text(payload)
                        except Exception:
                            dead.append(ws_client)
                    for d in dead:
                        connected_clients.discard(d)

            await asyncio.sleep(0.05)
        except Exception:
            await asyncio.sleep(0.1)


def build_telemetry_payload(engine):
    global _last_packet_count, _last_rate_time
    if not engine:
        return {}

    all_stats = engine.get_all_stats()
    meta = all_stats.get("metadata", {})
    dns = all_stats.get("dns", {})
    tls = all_stats.get("tls", {})
    http = all_stats.get("http", {})
    leaks = all_stats.get("leaks", {})
    vpn = all_stats.get("vpn_leak", {})
    trackers = all_stats.get("tracker", {})
    privacy = all_stats.get("privacy_score", {})

    now = time.time()
    dt = max(0.01, now - _last_rate_time)
    pkts = engine.packet_count
    pkt_rate = round(max(0, (pkts - _last_packet_count) / dt), 1)
    _last_packet_count = pkts
    _last_rate_time = now

    elapsed = engine.get_elapsed()
    elapsed_str = str(elapsed).split(".")[0] if elapsed else "00:00:00"

    # Protocol distribution
    total_proto = (tls.get("total_handshakes", 0) +
                   dns.get("total_queries", 0) +
                   http.get("total_requests", 0))
    if total_proto > 0:
        tls_pct = round((tls.get("total_handshakes", 0) / total_proto) * 100)
        dns_pct = round((dns.get("total_queries", 0) / total_proto) * 100)
        http_pct = round((http.get("total_requests", 0) / total_proto) * 100)
    else:
        tls_pct, dns_pct, http_pct = 50, 35, 15

    # Dossier snapshot
    dossier = None
    try:
        dossier = ISPDossier(all_stats).dossier
    except Exception:
        pass

    return {
        "interface": engine.interface,
        "elapsed": elapsed_str,
        "packets_captured": pkts,
        "events_logged": all_stats.get("events_logged", 0),
        "packet_rate": pkt_rate,
        "bytes_sent": meta.get("bytes_sent", 0),
        "bytes_received": meta.get("bytes_received", 0),
        "bytes_sent_formatted": bytes_to_human(meta.get("bytes_sent", 0)),
        "bytes_received_formatted": bytes_to_human(meta.get("bytes_received", 0)),
        "unique_destinations": meta.get("unique_destinations", 0),
        "unique_domains": dns.get("unique_domains", 0) + tls.get("unique_domains", 0),
        "privacy_score": privacy,
        "protocol_dist": {
            "tls": tls_pct,
            "dns": dns_pct,
            "http": http_pct,
        },
        "dossier": dossier,
    }


def get_active_engine():
    global global_engine
    if global_engine is None:
        # Default to synthetic simulation so web dashboard is instantly live
        global_engine = CaptureEngine(
            interface="sim-eth0",
            simulate=True,
            geo_enabled=False,
        )
        global_engine.start()
    return global_engine



def run_web_server(host="127.0.0.1", port=8080, engine=None, demo=True):
    """Launch the interactive web dashboard server."""
    global global_engine
    if engine:
        global_engine = engine
    elif demo:
        global_engine = CaptureEngine(
            interface="sim0",
            simulate=True,
            geo_enabled=False,
        )
        global_engine.start()

    print(f"\n[+] ISP Spy Mirror Web Dashboard running at: http://{host}:{port}")
    print(f"[+] Mode: {'Synthetic Privacy Simulation' if (global_engine and global_engine.simulate) else 'Live Network Monitor'}")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    run_web_server(host="127.0.0.1", port=8080, demo=True)
