import React, { useState } from "react";

export default function SimulationPanel() {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const api =
    import.meta.env.VITE_API_URL ||
    "http://localhost:8001"\;

  async function runSimulation() {
    setRunning(true);
    setError("");
    setResult(null);

    try {
      const simulation = await fetch(
        `${api}/simulation/run`,
        { method: "POST" }
      );

      if (!simulation.ok) {
        throw new Error("Simulation failed");
      }

      const data = await simulation.json();

      const detection = await fetch(
        `${api}/detect/run`,
        { method: "POST" }
      );

      if (!detection.ok) {
        throw new Error("Detection failed");
      }

      const alerts = await detection.json();

      setResult({ ...data, ...alerts });

    } catch (err) {
      setError(err.message);
    } finally {
      setRunning(false);
    }
  }

  return (
    <section style={{
      padding: "20px",
      margin: "16px",
      border: "1px solid #334155",
      borderRadius: "12px",
      background: "#0f172a",
      color: "#e2e8f0"
    }}>
      <h2>Adversary Simulation Lab</h2>

      <p>
        Generate synthetic security events and
        validate SentinelHub detection rules.
      </p>

      <button
        disabled={running}
        onClick={runSimulation}
        style={{
          background: "#2563eb",
          color: "white",
          padding: "10px 18px",
          borderRadius: "8px",
          border: "none",
          cursor: "pointer"
        }}
      >
        {running ? "Running..." : "Run Simulation"}
      </button>

      {result && (
        <div style={{ marginTop: "16px" }}>
          <p>Simulation completed</p>
          <p>
            Events generated: {result.events_generated}
          </p>
          <p>
            Events ingested: {result.events_ingested}
          </p>
          <p>
            New alerts: {result.new_alerts}
          </p>
        </div>
      )}

      {error && <p style={{ color: "salmon" }}>{error}</p>}
    </section>
  );
}
