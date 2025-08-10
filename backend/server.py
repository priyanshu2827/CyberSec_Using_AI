from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection (MUST use env)
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI(title="AI-driven Cybersecurity Simulator", version="1.0.0")

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


# ---------- Utility: Simple rule engine for prediction and blocking ----------
SUSPICIOUS_PORTS = {22, 3389, 445, 135}
SENSITIVE_PATHS = ["/etc", "/var/log", "c:/windows/system32", "c:/users"]
SUSPICIOUS_PROC_NAMES = ["powershell", "cmd", "wscript", "cscript", "mshta", "regsvr32"]


def analyze_telemetry(telemetry: Telemetry) -> Dict[str, Any]:
    indicators: List[Indicator] = []
    timeline: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []

    # Network analysis
    susp_net = 0
    for conn in telemetry.network_connections:
        port = int(conn.get("destination_port", 0))
        bytes_tx = int(conn.get("bytes_transferred", 0))
        domain = str(conn.get("destination_domain", "")).lower()
        if port in SUSPICIOUS_PORTS and str(conn.get("source_ip", "")).startswith(("10.", "192.168.", "172.")):
            indicators.append(Indicator(type="internal_admin_access", severity="medium",
                                        description=f"Internal admin port {port} to {conn.get('destination_ip')}",
                                        meta={"port": port}))
            timeline.append({"ts": datetime.utcnow().isoformat(), "event": "net_admin_port", "port": port})
            susp_net += 1
        if bytes_tx > 100_000_000:
            indicators.append(Indicator(type="high_volume_transfer", severity="high",
                                        description=f"Large transfer {bytes_tx} bytes to {conn.get('destination_ip')}",
                                        meta={"bytes": bytes_tx}))
            timeline.append({"ts": datetime.utcnow().isoformat(), "event": "net_large_xfer", "bytes": bytes_tx})
            susp_net += 1
        if any(ind in domain for ind in ["temp", "dyn", "bit.ly", "tinyurl"] if domain):
            indicators.append(Indicator(type="suspicious_domain", severity="high",
                                        description=f"Suspicious domain {domain}", meta={"domain": domain}))
            timeline.append({"ts": datetime.utcnow().isoformat(), "event": "net_susp_domain", "domain": domain})
            susp_net += 1

    # Process analysis
    susp_proc = 0
    for p in telemetry.process_list:
        name = str(p.get("name", "")).lower()
        cmd = str(p.get("command_line", "")).lower()
        if any(n in name for n in SUSPICIOUS_PROC_NAMES) and any(flag in cmd for flag in ["-enc", "-executionpolicy", "downloadstring", "invoke"]):
            indicators.append(Indicator(type="suspicious_script_execution", severity="high",
                                        description=f"Suspicious script execution {name}",
                                        meta={"pid": p.get("pid"), "cmd": cmd[:160]}))
            timeline.append({"ts": datetime.utcnow().isoformat(), "event": "proc_script", "name": name})
            # Simulate block
            blocked.append({"action": "kill_process", "pid": p.get("pid"), "reason": "script_execution"})
            susp_proc += 1
        if int(p.get("network_connections", 0)) > 10:
            indicators.append(Indicator(type="high_network_activity", severity="medium",
                                        description=f"High network activity {name}",
                                        meta={"count": p.get("network_connections")}))
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
                                            meta={"pid": pid, "count": len(logs), "types": list(file_types)}))
                timeline.append({"ts": datetime.utcnow().isoformat(), "event": "file_mass", "pid": pid})
                blocked.append({"action": "suspend_io", "pid": pid, "reason": "mass_file_access"})
                susp_file += 1
        for l in logs:
            fpath = str(l.get("file_path", "")).lower()
            if any(sp in fpath for sp in SENSITIVE_PATHS) and l.get("operation") in ("read", "copy"):
                indicators.append(Indicator(type="sensitive_file_access", severity="high",
                                            description=f"Sensitive path access {l.get('file_path')}",
                                            meta={"pid": pid, "op": l.get("operation")}))
                timeline.append({"ts": datetime.utcnow().isoformat(), "event": "file_sensitive", "pid": pid})
                susp_file += 1

    # Composite risk score (bounded 0-10)
    raw = susp_net * 1.5 + susp_proc * 2.0 + susp_file * 1.8
    risk_score = min(raw, 10.0)

    # Basic recommendations (no LLM yet; can be upgraded later via Emergent Integrations)
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
    }


# ---------- Routes ----------
@api.get("/")
async def root():
    return {"message": "AI-driven Cybersecurity Simulator API"}


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
    # validate scenario exists
    scenario = await db.scenarios.find_one({"id": payload.scenario_id})
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    analysis = analyze_telemetry(payload.telemetry)

    result = SimulationResult(
        scenario_id=payload.scenario_id,
        device_id=payload.telemetry.device_id,
        risk_score=analysis["risk_score"],
        indicators=[Indicator(**i) for i in analysis["indicators"]],
        recommendations=analysis["recommendations"],
        timeline=analysis["timeline"],
        blocked_actions=analysis["blocked"],
    )

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