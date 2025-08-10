import React, { useEffect, useMemo, useState } from "react";
import { getApi } from "../utils/api";
import { Link, useNavigate } from "react-router-dom";

export default function Landing() {
  const api = useMemo(() => getApi(), []);
  const [stats, setStats] = useState({ scenarios: 0, simulations: 0 });
  const [status, setStatus] = useState("Connecting...");
  const navigate = useNavigate();

  useEffect(() => {
    const load = async () => {
      try {
        const [root, sc, si] = await Promise.all([
          api.get("/"),
          api.get("/scenarios"),
          api.get("/simulations"),
        ]);
        setStatus(root?.data?.message || "Online");
        setStats({ scenarios: (sc.data || []).length, simulations: (si.data || []).length });
      } catch (e) {
        setStatus("Backend offline");
      }
    };
    load();
  }, []);

  return (
    <div className="landing">
      <section className="hero2">
        <div className="hero2-inner">
          <h1 className="title glow">AI-driven Cybersecurity Simulator</h1>
          <p className="lead">Design attack scenarios, run device checks, and get explainable threat insights with simulated blocking.</p>
          <div className="row" style={{ marginTop: 14 }}>
            <button className="btn" onClick={() => navigate("/simulate")}>Start Free Check</button>
            <Link to="/dashboard" className="btn ml" style={{ background: "#111827", border: "1px solid #1f2937" }}>Open Dashboard</Link>
          </div>
          <div className="landing-stats">
            <div className="stat2"><div className="stat2-num">{stats.scenarios}</div><div className="stat2-label">Scenarios</div></div>
            <div className="stat2"><div className="stat2-num">{stats.simulations}</div><div className="stat2-label">Simulations</div></div>
            <div className="stat2"><div className="stat2-num ok" /> <div className="stat2-label">{status}</div></div>
          </div>
        </div>
      </section>

      <section className="features">
        <div className="grid">
          <div className="card feat">
            <h3>Policy-Driven Detections</h3>
            <p>Explainable, tunable rules catch Powershell abuse, admin-ports from private ranges, exfiltration spikes, ransomware-like file bursts, and sensitive path reads.</p>
            <Link to="/policy" className="muted small">Tune thresholds via API (/api/policy)</Link>
          </div>
          <div className="card feat">
            <h3>Interactive Simulator</h3>
            <p>Paste telemetry JSON, run the engine, and inspect risk, indicators, timeline, and simulated block actions with one click.</p>
            <Link to="/simulate" className="btn" style={{ marginTop: 6 }}>Run Simulation</Link>
          </div>
          <div className="card feat">
            <h3>Live Device Foundation</h3>
            <p>Register devices and ingest telemetry securely. Upgrade to real-time blocking with a lightweight agent when ready.</p>
            <span className="muted small">POST /api/devices/register, POST /api/ingest</span>
          </div>
          <div className="card feat">
            <h3>Feedback &amp; Trust</h3>
            <p>Mark alerts as True/False Positive to reduce noise and drive future ML thresholding. Dedupe suppresses repeats.</p>
            <span className="muted small">/api/simulations/{`{id}`}/feedback</span>
          </div>
        </div>
      </section>

      <section className="cta">
        <div className="card">
          <div className="row between" style={{ alignItems: "center" }}>
            <div>
              <h3 className="glow" style={{ margin: 0 }}>Ready to see your risk?</h3>
              <div className="muted">Run a sample or feed your own telemetry to get instant, explainable results.</div>
            </div>
            <div className="row">
              <button className="btn" onClick={() => navigate("/simulate")}>Start Now</button>
              <Link className="btn ml" to="/scenarios">Design Scenarios</Link>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}