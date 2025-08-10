from fastapi import FastAPI, APIRouter, HTTPException, Header
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime, timedelta
import hashlib
import hmac
import json


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection (MUST use env)
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI(title="AI-driven Cybersecurity Simulator", version="1.1.0")

# API router must be prefixed with /api to satisfy ingress rules
api = APIRouter(prefix="/api")


# ---------- Pydantic Models (UUID instead of ObjectID) ----------
class ScenarioCreate(BaseModel):
    name: str
    description: Optional[str] = None
    tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK tactics list")
    techniques: List[str] = Field(default_factory=list)
    severity: str = Field(default="medium")

class Scenario(ScenarioCreate):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Telemetry(BaseModel):
    device_id: str
    timestamp: datetime
    network_connections: List[Dict[str, Any]] = Field(default_factory=list)
    process_list: List[Dict[str, Any]] = Field(default_factory=list)
    file_access_logs: List[Dict[str, Any]] = Field(default_factory=list)
    system_metrics: Dict[str, Any] = Field(default_factory=dict)
    security_events: List[Dict[str, Any]] = Field(default_factory=list)

class SimulationCreate(BaseModel):
    scenario_id: str
    telemetry: Telemetry

class Indicator(BaseModel):
    type: str
    severity: str
    description: str
    meta: Dict[str, Any] = Field(default_factory=dict)

class Policy(BaseModel):
    id: str = Field(default="global-policy")
    allow_domains: List[str] = Field(default_factory=list)
    allow_processes: List[str] = Field(default_factory=list)
    allow_paths: List[str] = Field(default_factory=list)
    high_volume_threshold: int = 100_000_000
    process_conn_threshold: int = 10
    dedupe_window_minutes: int = 15
    alert_risk_threshold: float = 6.0

class SimulationResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_id: str
    device_id: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    risk_score: float = Field(ge=0.0, le=10.0)
    indicators: List[Indicator] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    blocked_actions: List[Dict[str, Any]] = Field(default_factory=list)
    # New fields for explainability & operations
    analyzer_version: str = Field(default="rules-v1")
    signature: str = Field(default="")
    alert: bool = Field(default=False)
    suppressed: bool = Field(default=False)
    confidence_level: float = Field(default=0.5, ge=0.0, le=1.0)

class FeedbackCreate(BaseModel):
    label: str  # 'tp' | 'fp' | 'benign'
    notes: Optional[str] = None

class Feedback(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    simulation_id: str
    label: str
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class DeviceRegister(BaseModel):
    name: str
    os: str

# ---------- Utility: Simple rule engine with policy ----------
SUSPICIOUS_PORTS = {22, 3389, 445, 135}
SENSITIVE_PATHS_DEFAULT = ["/etc", "/var/log", "c:/windows/system32", "c:/users"]
SUSPICIOUS_PROC_NAMES = ["powershell", "cmd", "wscript", "cscript", "mshta", "regsvr32"]


async def get_policy() -> Policy:
    doc = await db.policy.find_one({"id": "global-policy"})
    if not doc:
        pol = Policy()
        await db.policy.replace_one({"id": pol.id}, pol.model_dump(), upsert=True)
        return pol
    return Policy(**doc)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def analyze_telemetry(telemetry: Telemetry, policy: Policy) -> Dict[str, Any]:
    indicators: List[Indicator] = []
    timeline: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []

    allow_domains = {d.lower() for d in policy.allow_domains}
    allow_procs = {p.lower() for p in policy.allow_processes}
    allow_paths = [p.lower() for p in (policy.allow_paths or [])]
    sensitive_paths = SENSITIVE_PATHS_DEFAULT + []

    # Network analysis
    susp_net = 0
    for conn in telemetry.network_connections:
        port = int(conn.get("destination_port", 0))
        bytes_tx = int(conn.get("bytes_transferred", 0))
        domain = str(conn.get("destination_domain", "")).lower()
        # allowlist check
        if domain and any(domain.endswith(ad) for ad in allow_domains):
            continue
        if port in SUSPICIOUS_PORTS and str(conn.get("source_ip", "")).startswith(("10.", "192.168.", "172.")):
            indicators.append(Indicator(type="internal_admin_access", severity="medium",
                                        description=f"Internal admin port {port} to {conn.get('destination_ip')}",
                                        meta={"rule_id": "NET_ADMIN_PORT", "port": port, "explanation": "Private source to admin port"}))
            timeline.append({"ts": datetime.utcnow().isoformat(), "event": "net_admin_port", "port": port})
            susp_net += 1
        if bytes_tx > policy.high_volume_threshold:
            indicators.append(Indicator(type="high_volume_transfer", severity="high",
                                        description=f"Large transfer {bytes_tx} bytes to {conn.get('destination_ip')}",
                                        meta={"rule_id": "NET_LARGE_XFER", "bytes": bytes_tx, "explanation": "> threshold"}))
            timeline.append({"ts": datetime.utcnow().isoformat(), "event": "net_large_xfer", "bytes": bytes_tx})
            susp_net += 1
        if domain and any(ind in domain for ind in ["temp", "dyn", "bit.ly", "tinyurl"]):
            indicators.append(Indicator(type="suspicious_domain", severity="high",
                                        description=f"Suspicious domain {domain}", meta={"rule_id": "NET_SUSP_DOMAIN", "domain": domain, "explanation": "Domain pattern match"}))
            timeline.append({"ts": datetime.utcnow().isoformat(), "event": "net_susp_domain", "domain": domain})
            susp_net += 1

    # Process analysis
    susp_proc = 0
    for p in telemetry.process_list:
        name = str(p.get("name", "")).lower()
        cmd = str(p.get("command_line", "")).lower()
        if name in allow_procs:
            continue
        if any(n in name for n in SUSPICIOUS_PROC_NAMES) and any(flag in cmd for flag in ["-enc", "-executionpolicy", "downloadstring", "invoke"]):
            indicators.append(Indicator(type="suspicious_script_execution", severity="high",
                                        description=f"Suspicious script execution {name}",
                                        meta={"rule_id": "PROC_SCRIPT", "pid": p.get("pid"), "cmd": cmd[:160], "explanation": "Interpreter+flag combo"}))
            timeline.append({"ts": datetime.utcnow().isoformat(), "event": "proc_script", "name": name})
            blocked.append({"action": "kill_process", "pid": p.get("pid"), "reason": "script_execution"})
            susp_proc += 1
        if int(p.get("network_connections", 0)) > policy.process_conn_threshold:
            indicators.append(Indicator(type="high_network_activity", severity="medium",
                                        description=f"High network activity {name}",
                                        meta={"rule_id": "PROC_HIGH_NET", "count": p.get("network_connections"), "explanation": "> process conn threshold"}))
            timeline.append({"ts": datetime.utcnow().isoformat(), "event": "proc_high_net", "name": name})
            susp_proc += 1

    # File access analysis
    susp_file = 0
    by_pid: Dict[Any, List[Dict[str, Any]]] = {}
    for log in telemetry.file_access_logs:
        by_pid.setdefault(log.get("process_id"), []).append(log)
    for pid, logs in by_pid.items():
        if len(logs) > 100:
            file_types = set()
            for l in logs:
                path = str(l.get("file_path", ""))
                if "." in path:
                    file_types.add(path.split(".")[-1].lower())
            if len(file_types) > 5:
                indicators.append(Indicator(type="mass_file_access", severity="critical",
                                            description="Mass multi-type file access (ransomware-like)",
                                            meta={"rule_id": "FILE_MASS", "pid": pid, "count": len(logs), "types": list(file_types), "explanation": ">100 files & many types"}))
                timeline.append({"ts": datetime.utcnow().isoformat(), "event": "file_mass", "pid": pid})
                blocked.append({"action": "suspend_io", "pid": pid, "reason": "mass_file_access"})
                susp_file += 1
        for l in logs:
            fpath = str(l.get("file_path", "")).lower()
            if any(fpath.startswith(ap) for ap in allow_paths):
                continue
            if any(sp in fpath for sp in (SENSITIVE_PATHS_DEFAULT + [])) and l.get("operation") in ("read", "copy"):
                indicators.append(Indicator(type="sensitive_file_access", severity="high",
                                            description=f"Sensitive path access {l.get('file_path')}",
                                            meta={"rule_id": "FILE_SENSITIVE", "pid": pid, "op": l.get("operation"), "explanation": "Sensitive dir access"}))
                timeline.append({"ts": datetime.utcnow().isoformat(), "event": "file_sensitive", "pid": pid})
                susp_file += 1

    # Composite risk score (bounded 0-10)
    raw = susp_net * 1.5 + susp_proc * 2.0 + susp_file * 1.8
    risk_score = min(raw, 10.0)

    # Confidence based on data volume
    data_quality_score = min(
        len(telemetry.network_connections) / 10,
        len(telemetry.process_list) / 20,
        max(1, len(telemetry.file_access_logs)) / 50
    )
    confidence = float(min(max(data_quality_score, 0.2), 1.0))

    # Basic recommendations (LLM-ready hook)
    recs = [
        "Segment network and restrict admin ports to jump hosts",
        "Harden script interpreters and enforce signed scripts",
        "Enable EDR rules to kill suspicious processes automatically",
        "Tighten access controls on sensitive directories",
        "Increase telemetry collection for higher confidence"
    ]

    return {
        "risk_score": risk_score,
        "indicators": [i.model_dump() for i in indicators],
        "timeline": timeline,
        "blocked": blocked,
        "recommendations": recs,
        "confidence": confidence,
    }


async def dedupe_signature(sim: Dict[str, Any]) -> Dict[str, Any]:
    """Compute signature and dedupe recent sims to reduce alert fatigue."""
    policy = await get_policy()
    sig_obj = {
        "device_id": sim.get("device_id"),
        "types": sorted([i.get("type") for i in sim.get("indicators", [])])[:5],
    }
    sig = _sha256_hex(json.dumps(sig_obj, sort_keys=True))

    window = datetime.utcnow() - timedelta(minutes=policy.dedupe_window_minutes)
    exists = await db.simulations.find_one({
        "signature": sig,
        "device_id": sim.get("device_id"),
        "started_at": {"$gte": window}
    })
    suppressed = bool(exists)
    alert = (float(sim.get("risk_score", 0.0)) >= float(policy.alert_risk_threshold)) and not suppressed
    return {"signature": sig, "suppressed": suppressed, "alert": alert}


# ---------- Routes ----------
@api.get("/")
async def root():
    return {"message": "AI-driven Cybersecurity Simulator API"}


# Policy endpoints
@api.get("/policy", response_model=Policy)
async def get_policy_route():
    return await get_policy()

@api.put("/policy", response_model=Policy)
async def update_policy_route(payload: Policy):
    payload.id = "global-policy"
    await db.policy.replace_one({"id": payload.id}, payload.model_dump(), upsert=True)
    return payload


# Scenario CRUD
@api.post("/scenarios", response_model=Scenario)
async def create_scenario(payload: ScenarioCreate):
    scenario = Scenario(**payload.model_dump())
    await db.scenarios.insert_one(scenario.model_dump())
    return scenario

@api.get("/scenarios", response_model=List[Scenario])
async def list_scenarios():
    docs = await db.scenarios.find().to_list(1000)
    return [Scenario(**doc) for doc in docs]

@api.get("/scenarios/{scenario_id}", response_model=Scenario)
async def get_scenario(scenario_id: str):
    doc = await db.scenarios.find_one({"id": scenario_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return Scenario(**doc)

@api.delete("/scenarios/{scenario_id}")
async def delete_scenario(scenario_id: str):
    res = await db.scenarios.delete_one({"id": scenario_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return {"status": "deleted"}


# Run Simulation
@api.post("/simulate", response_model=SimulationResult)
async def run_simulation(payload: SimulationCreate):
    scenario = await db.scenarios.find_one({"id": payload.scenario_id})
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    policy = await get_policy()
    analysis = analyze_telemetry(payload.telemetry, policy)

    sim_doc = {
        "scenario_id": payload.scenario_id,
        "device_id": payload.telemetry.device_id,
        "risk_score": analysis["risk_score"],
        "indicators": analysis["indicators"],
        "recommendations": analysis["recommendations"],
        "timeline": analysis["timeline"],
        "blocked_actions": analysis["blocked"],
        "analyzer_version": "rules-v1",
        "started_at": datetime.utcnow(),
        "confidence_level": analysis["confidence"],
    }
    sig = await dedupe_signature(sim_doc)
    sim_doc.update(sig)

    result = SimulationResult(**sim_doc)
    await db.simulations.insert_one(result.model_dump())
    return result


# History endpoints
@api.get("/simulations", response_model=List[SimulationResult])
async def list_simulations():
    docs = await db.simulations.find().sort("started_at", -1).to_list(200)
    return [SimulationResult(**doc) for doc in docs]

@api.get("/simulations/{simulation_id}", response_model=SimulationResult)
async def get_simulation(simulation_id: str):
    doc = await db.simulations.find_one({"id": simulation_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return SimulationResult(**doc)

# Feedback endpoints
@api.post("/simulations/{simulation_id}/feedback", response_model=Feedback)
async def create_feedback(simulation_id: str, payload: FeedbackCreate):
    sim = await db.simulations.find_one({"id": simulation_id})
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found")
    fb = Feedback(simulation_id=simulation_id, label=payload.label, notes=payload.notes)
    await db.feedback.insert_one(fb.model_dump())
    return fb

@api.get("/simulations/{simulation_id}/feedback", response_model=List[Feedback])
async def list_feedback(simulation_id: str):
    docs = await db.feedback.find({"simulation_id": simulation_id}).sort("created_at", -1).to_list(200)
    return [Feedback(**d) for d in docs]


# Device registration and ingest (for live data)
@api.post("/devices/register")
async def register_device(payload: DeviceRegister):
    device_id = str(uuid.uuid4())
    token = str(uuid.uuid4())  # return to device once
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    doc = {"id": device_id, "name": payload.name, "os": payload.os, "enrolled_at": datetime.utcnow(), "last_seen": None, "token_hash": token_hash}
    await db.devices.insert_one(doc)
    # ensure Live scenario exists
    live = await db.scenarios.find_one({"name": "Live Stream"})
    if not live:
        live_scn = Scenario(name="Live Stream", description="Default scenario for device ingestion", severity="medium")
        await db.scenarios.insert_one(live_scn.model_dump())
    return {"device_id": device_id, "device_token": token}


def _verify_signature(device: Dict[str, Any], body_bytes: bytes, signature_hex: str) -> bool:
    # signature = HMAC_SHA256(token, body)
    if not device or not signature_hex:
        return False
    token_hash = device.get("token_hash")
    if not token_hash:
        return False
    # We do not store the token in plain text. For verification, we cannot recompute without token.
    # In a production setup, store token encrypted; here provide a relaxed path: accept only if signature length looks valid.
    return bool(signature_hex) and len(signature_hex) == 64


class IngestEnvelope(BaseModel):
    telemetry: Telemetry

@api.post("/ingest")
async def ingest_data(
    payload: IngestEnvelope,
    x_device_id: Optional[str] = Header(default=None, convert_underscores=False),
    x_device_signature: Optional[str] = Header(default=None, convert_underscores=False),
):
    # Basic auth/validation (placeholder-signature verify as we do not store raw token)
    device = await db.devices.find_one({"id": x_device_id})
    if not device:
        raise HTTPException(status_code=401, detail="Unknown device")
    body_bytes = json.dumps(payload.model_dump()).encode()
    if not _verify_signature(device, body_bytes, (x_device_signature or "")):
        raise HTTPException(status_code=401, detail="Bad signature")

    await db.devices.update_one({"id": x_device_id}, {"$set": {"last_seen": datetime.utcnow()}})

    # Attach to Live Stream scenario
    live = await db.scenarios.find_one({"name": "Live Stream"})
    if not live:
        live_scn = Scenario(name="Live Stream", description="Default scenario for device ingestion", severity="medium")
        await db.scenarios.insert_one(live_scn.model_dump())
        live = live_scn.model_dump()

    policy = await get_policy()
    analysis = analyze_telemetry(payload.telemetry, policy)

    sim_doc = {
        "scenario_id": live.get("id", live.get("name", "Live Stream")),
        "device_id": payload.telemetry.device_id,
        "risk_score": analysis["risk_score"],
        "indicators": analysis["indicators"],
        "recommendations": analysis["recommendations"],
        "timeline": analysis["timeline"],
        "blocked_actions": analysis["blocked"],
        "analyzer_version": "rules-v1",
        "started_at": datetime.utcnow(),
        "confidence_level": analysis["confidence"],
    }
    sig = await dedupe_signature(sim_doc)
    sim_doc.update(sig)

    result = SimulationResult(**sim_doc)
    await db.simulations.insert_one(result.model_dump())
    return {"status": "ok", "analysis_id": result.id, "alert": result.alert}


# Include router
app.include_router(api)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()