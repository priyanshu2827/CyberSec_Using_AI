# AI-driven Cybersecurity Simulator (Full-stack: React + FastAPI + MongoDB)

A modern, interactive security simulator with an explainable rule engine, dashboard, scenario designer, simulation runner, and the foundation for live device ingestion. Built to be transparent, tunable, and production-friendly.

## Tech Stack
- Frontend: React 19 (CRACO), axios, Tailwind-style utility CSS (App.css). All API calls use REACT_APP_BACKEND_URL + "/api" (no hardcoded URLs)
- Backend: FastAPI, Pydantic v2, Motor (MongoDB async), UUID IDs everywhere (no Mongo ObjectId in API)
- Database: MongoDB via MONGO_URL from backend/.env
- Runtime: Supervisor (backend at 0.0.0.0:8001, frontend 3000). Kubernetes ingress routes /api → backend; others → frontend

## Key Features
- Dashboard (Home + /dashboard)
  - Live tiles, risk gauge, risk distribution, recent activity
  - Quick-run CTA creates a scenario (if none) and runs a simulation
  - Click latest simulations to view details in a modal
- Scenario Designer (/scenarios)
  - Create/list/delete scenarios with severity, tactics, techniques
- Simulator (/simulate)
  - Paste telemetry JSON, run analyzer, view risk, indicators, event timeline, and simulated block actions
- History (/history)
  - List of previous simulation runs with risk and timestamps
- Explainable detections
  - Indicators include rule_id and plain-English explanation
  - Confidence score reflects data quantity/coverage
- Policy engine
  - GET /api/policy and PUT /api/policy to control thresholds (exfil size, process net-conn count), allowlists, dedupe window, alert threshold
- Feedback loop
  - POST /api/simulations/{id}/feedback (label: tp|fp|benign, notes) and GET to retrieve feedback
- Live device foundation
  - POST /api/devices/register → { device_id, device_token }
  - POST /api/ingest with headers X-Device-Id + X-Device-Signature (placeholder signature) → analyze & store as "Live Stream" scenario

## Current Detection Coverage (Rule Engine)
- Powershell/LoTL with dangerous flags (PROC_SCRIPT)
- Internal admin ports from private ranges (NET_ADMIN_PORT)
- High-volume egress/exfil (> threshold) (NET_LARGE_XFER)
- Suspicious domain patterns (NET_SUSP_DOMAIN)
- High process network activity (> N connections) (PROC_HIGH_NET)
- Ransomware-like mass multi-type file access (FILE_MASS)
- Sensitive directory access (FILE_SENSITIVE)

Each indicator carries meta.rule_id and meta.explanation, a timeline event, and optional simulated block actions (kill_process, suspend_io).

## Blocking (Simulated vs Real)
- Simulated: Responses included in API result (blocked_actions)
- Real (with agent):
  - Windows: Stop-Process; New-NetFirewallRule; PowerShell Constrained Language Mode; AppLocker/WDAC
  - Linux: kill/pause; iptables/nftables; cgroups IO throttle; SELinux/AppArmor
  - macOS: launchd actions; pf rules; file watchers
  - Flow: Device posts telemetry → backend analyzes → backend stores directives → agent pulls/apply → dashboard updates

## API Overview (all under /api)
- Health/Root: GET /
- Policy: GET /policy, PUT /policy
- Scenarios: POST /scenarios, GET /scenarios, GET /scenarios/{id}, DELETE /scenarios/{id}
- Simulator: POST /simulate → SimulationResult
- History: GET /simulations, GET /simulations/{id}
- Feedback: POST /simulations/{id}/feedback, GET /simulations/{id}/feedback
- Live device: POST /devices/register, POST /ingest

## Data Models
- Scenario: { id, name, description?, tactics[], techniques[], severity, created_at }
- Telemetry: { device_id, timestamp, network_connections[], process_list[], file_access_logs[], system_metrics{}, security_events[] }
- SimulationResult: { id, scenario_id, device_id, started_at, risk_score, indicators[], recommendations[], timeline[], blocked_actions[], analyzer_version, signature, alert, suppressed, confidence_level }
- Policy: { id, allow_domains[], allow_processes[], allow_paths[], high_volume_threshold, process_conn_threshold, dedupe_window_minutes, alert_risk_threshold }
- Feedback: { id, simulation_id, label, notes?, created_at }
- Device: { id, name, os, enrolled_at, last_seen?, token_hash }

## Environment Rules (do not change)
- Frontend must use REACT_APP_BACKEND_URL from frontend/.env and append "/api"
- Backend uses MONGO_URL and DB_NAME from backend/.env; bind on 0.0.0.0:8001
- All backend routes are prefixed with /api (Ingress requirement)

## Running & Service Control
- Everything runs via supervisor already
- Restart services when needed:
  - sudo supervisorctl restart frontend
  - sudo supervisorctl restart backend
  - sudo supervisorctl restart all

## Development Tips
- Backend logs: tail -n 100 /var/log/supervisor/backend.*.log
- Frontend logs: tail -n 100 /var/log/supervisor/frontend.*.log
- Test quickly:
  - curl http://127.0.0.1:8001/api/
  - curl -X POST http://127.0.0.1:8001/api/scenarios -H 'Content-Type: application/json' -d '{"name":"Ransomware","severity":"high"}'

## Roadmap (AI)
- Add Isolation Forest anomaly module + SHAP explanations
- ONNX Runtime for sequence model (Transformer lite) with INT8 quantization
- Emergent LLM for readable remediation and timeline narratives (uses EMERGENT_LLM_KEY)
- Agent for Windows/Linux/macOS with HMAC-secured ingest and directive enforcement

## License
Use responsibly. This is a simulator and should be tested on systems you are authorized to monitor.