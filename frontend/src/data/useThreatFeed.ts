import { useEffect, useRef, useState } from "react";
import type { Alert, FeedState, PacketSample, Severity } from "../types/alert";
import {
  DEMO_SCRIPT,
  MODELS,
  THREAT_TO_TACTIC,
  basePps,
  emptyMitre,
  makeBenign,
  phaseFor,
} from "./mockFeed";

/**
 * ── Live backend switch ───────────────────────────────────────────────
 * Set to your NetSentinel WebSocket to consume real alerts:
 *   const WS_URL = "ws://localhost:8000/ws";
 *
 * Empty string ("") = mock mode (the scripted 60-second demo). Note the
 * Figma Make preview sandbox cannot reach localhost, so live mode only
 * works when this app runs on the same host as `python run.py`
 * (see LOCAL_RUN.md). If the socket fails to open within 4s, we fall
 * back to mock automatically so the dashboard is never blank.
 * ──────────────────────────────────────────────────────────────────────
 */
const WS_URL = "ws://localhost:8000/ws";  // Changed from "" to enable live mode

const LOOP_MS = 60_000;
const TICK_MS = 900;
const MAX_ALERTS = 50;
const MAX_SAMPLES = 60;

const zeroCounts = (): Record<Severity, number> => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
});

function initialState(): FeedState {
  return {
    alerts: [],
    packetRate: [],
    threatCounts: zeroCounts(),
    models: MODELS.map((m) => ({ ...m })),
    mitre: emptyMitre(),
    totalFlows: 0,
    flowsPerSec: 42.5,
    phase: phaseFor(0),
    status: "monitoring",
    source: "mock",
  };
}

/**
 * Transform backend alert schema → frontend Alert interface.
 * 
 * Backend schema (from alert_manager.py):
 *   - timestamp: ISO 8601 string
 *   - confidence: float 0-1
 *   - severity: UPPERCASE
 *   - threat_class: snake_case
 *   - mitre: nested object
 *   - evidence: dict
 *   - geo: nested object
 * 
 * Frontend schema (types/alert.ts):
 *   - timestamp: epoch ms
 *   - confidence: 0-100 percentage
 *   - severity: lowercase
 *   - threatType: camelCase
 *   - mitreTechnique/mitreTactic: flat
 *   - indicators: string array
 *   - sourceCoords/destCoords: [lat, lng] tuples
 */

// Map backend model names → frontend display names
const MODEL_NAME_MAP: Record<string, string> = {
  "ddos_binary_xgboost": "DDoS XGBoost",
  "dga_cnn_bilstm": "DGA CNN-BiLSTM",
  "c2_beacon_bilstm_fft": "C2 BiLSTM+FFT",
  "encrypted_traffic_transformer": "ETT Transformer",
  "port_scan_xgboost": "Port Scan XGBoost",
  "exfil_vae": "Exfil VAE",
};

function parseBackendAlert(raw: any): Alert {
  // Transform evidence dict → human-readable indicators array
  const indicators: string[] = [];
  if (raw.evidence) {
    if (raw.evidence.pps) indicators.push(`${raw.evidence.pps.toLocaleString()} pps`);
    if (raw.evidence.avg_pkt_size) indicators.push(`Avg packet size: ${raw.evidence.avg_pkt_size} bytes`);
    if (raw.evidence.syn_ack_ratio !== undefined) indicators.push(`SYN/ACK ratio: ${raw.evidence.syn_ack_ratio.toFixed(2)}`);
    if (raw.evidence.beacon_interval) indicators.push(`Beacon interval: ${raw.evidence.beacon_interval}s`);
    if (raw.evidence.entropy) indicators.push(`Entropy: ${raw.evidence.entropy.toFixed(2)}`);
    if (raw.evidence.domain) indicators.push(`Domain: ${raw.evidence.domain}`);
    // Add more evidence field mappings as backend evolves
  }

  // Fallback indicators if evidence is empty
  if (indicators.length === 0) {
    indicators.push(`Detected by ${raw.model_name || "ML model"}`);
  }

  return {
    id: raw.id,
    timestamp: new Date(raw.timestamp).getTime(), // ISO → epoch ms
    threatType: raw.threat_class as Alert["threatType"],
    severity: raw.severity.toLowerCase() as Severity,
    sourceIP: raw.source_ip,
    destIP: raw.dest_ip,
    domain: raw.evidence?.domain,
    confidence: Math.round(raw.confidence * 1000) / 10, // 0.9937 → 99.4
    mitreTechnique: raw.mitre?.technique,
    mitreTactic: raw.mitre?.tactic,
    model: MODEL_NAME_MAP[raw.model_name] || raw.model_name as Alert["model"],
    indicators,
    beaconInterval: raw.evidence?.beacon_interval,
    // Transform geo object → coordinate tuples for 3D graph
    sourceCoords: raw.geo?.src_lat && raw.geo?.src_lon 
      ? [raw.geo.src_lat, raw.geo.src_lon] 
      : undefined,
    destCoords: raw.geo?.dst_lat && raw.geo?.dst_lon 
      ? [raw.geo.dst_lat, raw.geo.dst_lon] 
      : undefined,
  };
}

// Fold a single alert into feed state. Shared by mock + live paths so
// downstream aggregation is identical regardless of source.
function ingest(prev: FeedState, alert: Alert, source: FeedState["source"]): FeedState {
  const alerts = [alert, ...prev.alerts].slice(0, MAX_ALERTS);
  const threatCounts = { ...zeroCounts() };
  for (const a of alerts) threatCounts[a.severity] += 1;

  const models = prev.models.map((m) =>
    m.name === alert.model
      ? { ...m, active: true, lastConfidence: alert.confidence }
      : { ...m, active: false },
  );

  const mitre = prev.mitre.map((c) => ({ ...c }));
  const tactic = THREAT_TO_TACTIC[alert.threatType];
  if (tactic && alert.mitreTechnique) {
    const cell =
      mitre.find((c) => c.tactic === tactic && c.technique.startsWith(alert.mitreTechnique!.slice(0, 4))) ??
      mitre.find((c) => c.tactic === tactic);
    if (cell) cell.hits += 1;
  }

  const status: FeedState["status"] =
    alert.severity === "critical" ? "critical" : prev.status === "critical" ? "critical" : "monitoring";

  return { ...prev, alerts, threatCounts, models, mitre, status, source };
}

export function useThreatFeed(): FeedState {
  const [state, setState] = useState<FeedState>(initialState);
  const start = useRef(Date.now());
  const firedRef = useRef<Set<number>>(new Set());

  useEffect(() => {
    let ws: WebSocket | null = null;
    let mockIv: ReturnType<typeof setInterval> | null = null;
    let sampleIv: ReturnType<typeof setInterval> | null = null;
    let fallbackTimer: ReturnType<typeof setTimeout> | null = null;
    let live = false;

    // Chart samples run in BOTH modes so the packet-rate plot always moves.
    const startSampling = (isLive: boolean) => {
      sampleIv = setInterval(() => {
        const now = Date.now();
        const elapsed = (now - start.current) % LOOP_MS;
        setState((prev) => {
          const recent = prev.alerts.filter((a) => now - a.timestamp < 3000);
          const sample: PacketSample = {
            t: now,
            pps: isLive ? 800 + recent.length * 400 + Math.random() * 200 : basePps(elapsed),
            critical: recent.filter((a) => a.severity === "critical").length,
            high: recent.filter((a) => a.severity === "high").length,
            medium: recent.filter((a) => a.severity === "medium").length,
          };
          const packetRate = [...prev.packetRate, sample].slice(-MAX_SAMPLES);
          const flowsPerSec = +(40 + Math.random() * 6).toFixed(1);
          return {
            ...prev,
            packetRate,
            totalFlows: prev.totalFlows + Math.round(flowsPerSec * (TICK_MS / 1000)),
            flowsPerSec,
            phase: isLive ? "Live capture" : phaseFor(elapsed),
          };
        });
      }, TICK_MS);
    };

    const startMock = () => {
      if (live) return;
      setState((prev) => ({ ...prev, source: "mock" }));
      startSampling(false);
      mockIv = setInterval(() => {
        const now = Date.now();
        const elapsed = (now - start.current) % LOOP_MS;
        const loopIndex = Math.floor((now - start.current) / LOOP_MS);
        const phase = phaseFor(elapsed);
        const fired = firedRef.current;

        DEMO_SCRIPT.forEach((ev, i) => {
          const key = loopIndex * 100 + i;
          if (elapsed >= ev.atMs && elapsed < ev.atMs + TICK_MS && !fired.has(key)) {
            fired.add(key);
            setState((prev) => ({ ...ingest(prev, ev.make(), "mock"), phase }));
          }
        });
        if (fired.size > 400) firedRef.current = new Set();
        if (Math.random() < 0.5) {
          setState((prev) => ({ ...ingest(prev, makeBenign(), "mock"), phase }));
        }
      }, TICK_MS);
    };

    if (WS_URL) {
      setState((prev) => ({ ...prev, status: "connecting" }));
      try {
        ws = new WebSocket(WS_URL);
        fallbackTimer = setTimeout(() => {
          if (!live) {
            console.log("[WebSocket] Fallback to mock after 4s timeout");
            startMock();
          }
        }, 4000);
        ws.onopen = () => {
          console.log("[WebSocket] Connected to backend:", WS_URL);
          live = true;
          if (fallbackTimer) clearTimeout(fallbackTimer);
          setState((prev) => ({ ...prev, source: "live", status: "monitoring" }));
          startSampling(true);
        };
        ws.onmessage = (e) => {
          try {
            const rawAlert = JSON.parse(e.data);
            // Handle backend message format: {"type": "alert", "data": {...}}
            const alertData = rawAlert.type === "alert" && rawAlert.data ? rawAlert.data : rawAlert;
            const alert = parseBackendAlert(alertData);
            setState((prev) => ingest(prev, alert, "live"));
          } catch (err) {
            console.warn("[WebSocket] Failed to parse alert:", err);
            /* ignore malformed frames */
          }
        };
        ws.onerror = (error) => {
          console.error("[WebSocket] Error:", error);
          if (!live) startMock();
        };
        ws.onclose = (event) => {
          console.log("[WebSocket] Closed:", event.code, event.reason);
          if (!live) startMock();
        };
      } catch (error) {
        console.error("[WebSocket] Failed to create connection:", error);
        startMock();
      }
    } else {
      startMock();
    }

    return () => {
      ws?.close();
      if (mockIv) clearInterval(mockIv);
      if (sampleIv) clearInterval(sampleIv);
      if (fallbackTimer) clearTimeout(fallbackTimer);
    };
  }, []);

  return state;
}
