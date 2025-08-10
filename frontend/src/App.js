import { useEffect, useMemo, useState } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route, Link, useLocation } from "react-router-dom";
import axios from "axios";
import Dashboard from "./components/Dashboard";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

function useApi() {
  const api = useMemo(() => {
    const inst = axios.create({ baseURL: API, timeout: 30000 });
    return inst;
  }, []);
  return api;
}

const Nav = () => {
  const { pathname } = useLocation();
  return (
    <div className="nav">
      <div className="nav-inner">
        <Link to="/" className="brand">AI Cyber Simulator</Link>
        <div className="nav-links">
          <Link className={pathname==="/"?"active":""} to="/">Dashboard</Link>
          <Link className={pathname==="/scenarios"?"active":""} to="/scenarios">Scenarios</Link>
          <Link className={pathname==="/simulate"?"active":""} to="/simulate">Simulate</Link>
          <Link className={pathname==="/history"?"active":""} to="/history">History</Link>
        </div>
      </div>
    </div>
  );
};

const ScenarioDesigner = () => {
  const api = useApi();
  const [scenarios, setScenarios] = useState([]);
  const [form, setForm] = useState({ name: "", description: "", severity: "medium", tactics: "", techniques: "" });
  const load = async () => {
    const res = await api.get("/scenarios");
    setScenarios(res.data);
  };
  useEffect(() => { load(); }, []);

  const create = async () => {
    const payload = {
      name: form.name,
      description: form.description,
      severity: form.severity,
      tactics: form.tactics ? form.tactics.split(",").map((s) => s.trim()) : [],
      techniques: form.techniques ? form.techniques.split(",").map((s) => s.trim()) : [],
    };
    await api.post("/scenarios", payload);
    await load();
    setForm({ name: "", description: "", severity: "medium", tactics: "", techniques: "" });
  };
  const remove = async (id) => {
    await api.delete(`/scenarios/${id}`);
    await load();
  };

  return (
    <div className="page">
      <h2>Scenario Designer</h2>
      <div className="card">
        <div className="row">
          <input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
        </div>
        <textarea placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        <div className="row">
          <input placeholder="Tactics (comma separated)" value={form.tactics} onChange={(e) => setForm({ ...form, tactics: e.target.value })} />
          <input placeholder="Techniques (comma separated)" value={form.techniques} onChange={(e) => setForm({ ...form, techniques: e.target.value })} />
        </div>
        <button className="btn" onClick={create}>Create Scenario</button>
      </div>

      <div className="list">
        {scenarios.map((s) => (
          <div className="card" key={s.id}>
            <div className="row between">
              <div>
                <b>{s.name}</b>
                <div className={`tag ${s.severity}`}>{s.severity}</div>
              </div>
              <button className="btn danger" onClick={() => remove(s.id)}>Delete</button>
            </div>
            {s.description && <p className="muted">{s.description}</p>}
            {(s.tactics?.length || s.techniques?.length) ? (
              <div className="muted small">
                <div>Tactics: {s.tactics?.join(", ")}</div>
                <div>Techniques: {s.techniques?.join(", ")}</div>
              </div>
            ) : null}
          </div>
        ))}
      </div>
    </div>
  );
};

const sampleTelemetry = () => ({
  device_id: "WORKSTATION-001",
  timestamp: new Date().toISOString(),
  network_connections: [
    { source_ip: "192.168.1.10", destination_ip: "203.0.113.10", destination_port: 443, protocol: "TCP", bytes_transferred: 150000000, destination_domain: "temp-malicious.biz" },
    { source_ip: "192.168.1.10", destination_ip: "192.168.1.5", destination_port: 22, protocol: "TCP", bytes_transferred: 2000 },
  ],
  process_list: [
    { name: "powershell.exe", pid: 1234, command_line: "powershell -ExecutionPolicy Bypass -enc AAA", network_connections: 15 },
    { name: "chrome.exe", pid: 5678, command_line: "chrome --flag", network_connections: 3 },
  ],
  file_access_logs: Array.from({ length: 150 }).map((_, i) => ({ process_id: 1234, file_path: `/home/user/file${i}.${["pdf","docx","xlsx","txt"][i%4]}`, operation: "read", timestamp: new Date().toISOString() })),
  system_metrics: { cpu_usage: 80.4, memory_usage: 70.1 },
  security_events: []
});

const Simulate = () => {
  const api = useApi();
  const [scenarios, setScenarios] = useState([]);
  const [scenarioId, setScenarioId] = useState("");
  const [telemetry, setTelemetry] = useState(sampleTelemetry());
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  useEffect(() => { (async () => { const res = await api.get("/scenarios"); setScenarios(res.data); if (res.data[0]) setScenarioId(res.data[0].id); })(); }, []);

  const run = async () => {
    if (!scenarioId) return;
    setLoading(true);
    try {
      const res = await api.post("/simulate", { scenario_id: scenarioId, telemetry });
      setResult(res.data);
    } catch (e) {
      console.error(e);
      alert("Simulation failed");
    } finally { setLoading(false); }
  };

  return (
    <div className="page">
      <h2>Run Simulation</h2>
      <div className="card">
        <div className="row">
          <select value={scenarioId} onChange={(e) => setScenarioId(e.target.value)}>
            <option value="">Select Scenario</option>
            {scenarios.map((s) => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
          <button className="btn" onClick={run} disabled={!scenarioId || loading}>{loading ? "Running..." : "Run"}</button>
        </div>
        <textarea rows={10} value={JSON.stringify(telemetry, null, 2)} onChange={(e) => {
          try { setTelemetry(JSON.parse(e.target.value)); } catch (err) {}
        }} />
      </div>

      {result && (
        <div className="grid">
          <div className="card">
            <h3>Summary</h3>
            <div className="row">
              <div className={`pill risk`}>Risk: {Number(result.risk_score).toFixed(1)}/10</div>
              <div className="pill">Indicators: {result.indicators?.length || 0}</div>
              <div className="pill">Blocked: {result.blocked_actions?.length || 0}</div>
            </div>
            <h4>Recommendations</h4>
            <ul>
              {(result.recommendations||[]).map((r, i) => <li key={i}>{r}</li>)}
            </ul>
          </div>
          <div className="card">
            <h3>Event Timeline</h3>
            <div className="timeline">
              {(result.timeline||[]).map((t, i) => (
                <div key={i} className="timeline-item">
                  <div className="time">{t.ts}</div>
                  <div className="evt">{t.event}</div>
                </div>
              ))}
            </div>
          </div>
          <div className="card">
            <h3>Indicators</h3>
            {(result.indicators||[]).map((ind, i) => (
              <div key={i} className={`indicator ${ind.severity}`}>
                <div className="row between">
                  <b>{ind.type}</b>
                  <span className={`tag ${ind.severity}`}>{ind.severity}</span>
                </div>
                <div className="muted small">{ind.description}</div>
              </div>
            ))}
          </div>
          <div className="card">
            <h3>Blocked Actions (Simulated)</h3>
            {(result.blocked_actions||[]).length ? (
              <ul>
                {result.blocked_actions.map((b, i) => <li key={i}><code>{b.action}</code> - {b.reason} {b.pid ? `(pid: ${b.pid})` : ""}</li>)}
              </ul>
            ) : <div className="muted">No actions blocked</div>}
          </div>
        </div>
      )}
    </div>
  );
};

const History = () => {
  const api = useApi();
  const [items, setItems] = useState([]);
  useEffect(() => { (async () => { const res = await api.get("/simulations"); setItems(res.data); })(); }, []);
  return (
    <div className="page">
      <h2>Simulation History</h2>
      <div className="list">
        {items.map((it) => (
          <div className="card" key={it.id}>
            <div className="row between">
              <div>
                <b>{it.device_id}</b>
                <div className="muted small">{new Date(it.started_at).toLocaleString()}</div>
              </div>
              <div className="pill">Risk {Number(it.risk_score).toFixed(1)}</div>
            </div>
            <div className="muted small">Scenario: {it.scenario_id}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <Nav />
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scenarios" element={<ScenarioDesigner />} />
          <Route path="/simulate" element={<Simulate />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;