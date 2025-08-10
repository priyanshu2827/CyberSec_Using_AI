/* Modal to show detailed simulation results */
import React from "react";

export default function SimulationDetails({ sim, onClose }) {
  if (!sim) return null;
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="row between">
          <h3>Simulation Detail</h3>
          <button className="btn" onClick={onClose}>Close</button>
        </div>
        <div className="row" style={{ gap: 16, flexWrap: "wrap" }}>
          <div className="pill risk">Risk: {Number(sim.risk_score).toFixed(1)}/10</div>
          <div className="pill">Device: {sim.device_id}</div>
          <div className="pill">Scenario: {sim.scenario_id}</div>
          <div className="pill">When: {new Date(sim.started_at).toLocaleString()}</div>
        </div>
        <div className="grid" style={{ marginTop: 16 }}>
          <div className="card">
            <h4>Indicators</h4>
            {(sim.indicators || []).map((ind, idx) => (
              <div className={`indicator ${ind.severity}`} key={idx}>
                <div className="row between">
                  <b>{ind.type}</b>
                  <span className={`tag ${ind.severity}`}>{ind.severity}</span>
                </div>
                <div className="muted small">{ind.description}</div>
              </div>
            ))}
          </div>
          <div className="card">
            <h4>Event Timeline</h4>
            <div className="timeline">
              {(sim.timeline || []).map((t, i) => (
                <div key={i} className="timeline-item">
                  <div className="time">{t.ts}</div>
                  <div className="evt">{t.event}</div>
                </div>
              ))}
            </div>
          </div>
          <div className="card">
            <h4>Blocked Actions</h4>
            {(sim.blocked_actions || []).length ? (
              <ul>
                {sim.blocked_actions.map((b, i) => (
                  <li key={i}><code>{b.action}</code> - {b.reason} {b.pid ? `(pid: ${b.pid})` : ""}</li>
                ))}
              </ul>
            ) : (
              <div className="muted">None</div>
            )}
          </div>
          <div className="card">
            <h4>Recommendations</h4>
            <ul>
              {(sim.recommendations || []).map((r, i) => <li key={i}>{r}</li>)}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}