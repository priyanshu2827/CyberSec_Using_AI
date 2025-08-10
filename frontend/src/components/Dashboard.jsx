import React, { useEffect, useMemo, useState } from "react";
import { getApi } from "../utils/api";

const bins = [
  { label: "0-2", min: 0, max: 2 },
  { label: "2-4", min: 2, max: 4 },
  { label: "4-6", min: 4, max: 6 },
  { label: "6-8", min: 6, max: 8 },
  { label: "8-10", min: 8, max: 10.1 },
];

import SimulationDetails from "./SimulationDetails";

export default function Dashboard({ onQuickRunComplete }) {
  const api = useMemo(() => getApi(), []);
  const [scenarios, setScenarios] = useState([]);
  const [sims, setSims] = useState([]);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState("");

  const load = async () => {
    const [sc, si] = await Promise.all([
      api.get("/scenarios"),
      api.get("/simulations"),
    ]);
    setScenarios(sc.data || []);
    setSims(si.data || []);
  };

  useEffect(() => {
    load();
    const t = setInterval(() => { load().catch(()=>{}); }, 5000);
    return () => clearInterval(t);
  }, []);

  const last24h = useMemo(() => {
    const dayAgo = Date.now() - 24 * 3600 * 1000;
    return sims.filter((s) => new Date(s.started_at).getTime() >= dayAgo);
  }, [sims]);

  const avgRisk = useMemo(() => {
    if (!sims.length) return 0;
    const n = Math.min(10, sims.length);
    const slice = sims.slice(0, n);
    const sum = slice.reduce((acc, s) => acc + (Number(s.risk_score) || 0), 0);
    return sum / n;
  }, [sims]);

  const riskDist = useMemo(() => {
    const map = {};
    bins.forEach((b) => (map[b.label] = 0));
    sims.forEach((s) => {
      const r = Number(s.risk_score) || 0;
      const bin = bins.find((b) => r >= b.min && r < b.max);
      if (bin) map[bin.label] += 1;
    });
    return map;
  }, [sims]);

  const latest = sims[0];

  const riskGaugeStyle = useMemo(() => {
    const value = Math.max(0, Math.min(10, Number(latest?.risk_score || 0)));
    const pct = (value / 10) * 100;
    return { background: `conic-gradient(#22c55e ${Math.min(pct,40)}%, #eab308 ${Math.max(0,Math.min(pct-40,40))}%, #ef4444 ${Math.max(0,pct-80)}%, #111317 0)` };
  }, [latest]);

  const showToast = (m) => {
    setToast(m);
    setTimeout(() => setToast(""), 2500);
  };

  const sampleTelemetry = () => ({
    device_id: "DASH-QUICK-DEVICE",
    timestamp: new Date().toISOString(),
    network_connections: [
      { source_ip: "192.168.1.10", destination_ip: "203.0.113.10", destination_port: 443, protocol: "TCP", bytes_transferred: 150000000, destination_domain: "temp-malicious.biz" },
      { source_ip: "192.168.1.10", destination_ip: "192.168.1.5", destination_port: 22, protocol: "TCP", bytes_transferred: 2000 }
    ],
    process_list: [
      { name: "powershell.exe", pid: 1234, command_line: "powershell -ExecutionPolicy Bypass -enc AAA", network_connections: 15 },
    ],
    file_access_logs: [],
    system_metrics: { cpu_usage: 70.4 },
    security_events: []
  });

  const runQuick = async () => {
    setLoading(true);
    try {
      let scenarioId = scenarios[0]?.id;
      if (!scenarioId) {
        const created = await api.post("/scenarios", {
          name: "Quick Start",
          description: "Auto-created for dashboard quick run",
          severity: "medium",
          tactics: ["TA0001"],
          techniques: ["T1059"]
        });
        scenarioId = created.data.id;
        await load();
      }
      const res = await api.post("/simulate", { scenario_id: scenarioId, telemetry: sampleTelemetry() });
      showToast("Quick simulation completed");
      await load();
      onQuickRunComplete && onQuickRunComplete(res.data);
    } catch (e) {
      console.error(e);
      showToast("Quick run failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page">
      <div className="hero dark-gradient">
        <div>
          <h1 className="title glow">Cybersecurity Dashboard</h1>
          <p className="muted">Live view into scenarios, simulations, and risks across your devices.</p>
          <div className="row" style={{ marginTop: 12 }}>
            <button className="btn" onClick={runQuick} disabled={loading}>{loading ? "Running..." : "Run Quick Check"}</button>
          </div>
        </div>
      </div>

      <div className="grid" style={{ marginTop: 16 }}>
        <div className="card stat">
          <div className="stat-label">Scenarios</div>
          <div className="stat-value">{scenarios.length}</div>
        </div>
        <div className="card stat">
          <div className="stat-label">Simulations</div>
          <div className="stat-value">{sims.length}</div>
        </div>
        <div className="card stat">
          <div className="stat-label">Last 24h</div>
          <div className="stat-value">{last24h.length}</div>
        </div>
        <div className="card stat">
          <div className="stat-label">Avg Risk (last 10)</div>
          <div className="stat-value">{avgRisk.toFixed(1)}</div>
        </div>
      </div>

      <div className="grid" style={{ marginTop: 16 }}>
        <div className="card">
          <h3>Latest Simulation</h3>
          {latest ? (
            <div className="row" style={{ alignItems: "center", gap: 16 }}>
              <div className="gauge" style={riskGaugeStyle}>
                <div className="gauge-inner">{Number(latest.risk_score).toFixed(1)}</div>
              </div>
              <div>
                <div className="muted small">Device</div>
                <div>{latest.device_id}</div>
                <div className="muted small" style={{ marginTop: 6 }}>Started</div>
                <div>{new Date(latest.started_at).toLocaleString()}</div>
              </div>
            </div>
          ) : (
            <div className="muted">No simulations yet</div>
          )}
        </div>
        <div className="card">
          <h3>Risk Distribution</h3>
          <div className="bars">
            {bins.map((b) => {
              const count = riskDist[b.label] || 0;
              const max = Math.max(1, ...Object.values(riskDist));
              const pct = Math.round((count / max) * 100);
              return (
                <div className="bar-row" key={b.label}>
                  <div className="bar-label">{b.label}</div>
                  <div className="bar-track"><div className="bar-fill" style={{ width: `${pct}%` }} /></div>
                  <div className="bar-count">{count}</div>
                </div>
              );
            })}
          </div>
        </div>
        <div className="card">
          <h3>Recent Activity</h3>
          <div className="timeline">
            {sims.slice(0, 8).map((s, i) => (
              <div className="timeline-item" key={i}>
                <div className="time">{new Date(s.started_at).toLocaleTimeString()}</div>
                <div className="evt">{s.device_id} • Risk {Number(s.risk_score).toFixed(1)}</div>
              </div>
            ))}
            {!sims.length && <div className="muted">No recent activity</div>}
          </div>
        </div>
        <div className="card">
          <h3>Latest Simulations</h3>
          <div className="table">
            <div className="thead"><div>Device</div><div>Scenario</div><div>Risk</div><div>When</div></div>
            <div className="tbody">
              {sims.slice(0, 8).map((s, i) => (
                <div key={i} className="trow" onClick={() => setSelected(s)} style={{cursor:'pointer'}}> 
                  <div>{s.device_id}</div>
                  <div className="muted small">{s.scenario_id}</div>
                  <div><span className="pill">{Number(s.risk_score).toFixed(1)}</span></div>
                  <div className="muted small">{new Date(s.started_at).toLocaleString()}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {selected && <SimulationDetails sim={selected} onClose={() => setSelected(null)} />}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}