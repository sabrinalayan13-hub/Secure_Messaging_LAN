import React, { useEffect, useMemo, useRef, useState } from "react";

/**
 * CONFIG
 * Adjust these for your FastAPI server.
 */
const API_BASE = "http://127.0.0.1:8000";
const WS_BASE = "ws://127.0.0.1:8000/ws";

/**
 * JWT helpers (client-side decode only; do NOT use this to "secure" anything).
 * Admin-only features must be enforced by the backend.
 */
function decodeJwt(token) {
  try {
    const [, payloadB64] = token.split(".");
    const json = atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/**
 * Placeholder crypto
 * Replace with real E2EE:
 * - X25519 for key agreement + XChaCha20-Poly1305 for encryption, or
 * - libsodium-wrappers, tweetnacl, WebCrypto, etc.
 *
 * For now: "encrypt" = base64 of plaintext, "decrypt" = base64 decode.
 * This demonstrates the flow without implying security.
 */
function encryptForRecipient(plaintext) {
  return btoa(unescape(encodeURIComponent(plaintext)));
}
function decryptFromSender(ciphertext) {
  try {
    return decodeURIComponent(escape(atob(ciphertext)));
  } catch {
    return "[Unable to decrypt]";
  }
}

function Section({ title, children }) {
  return (
    <div style={{ border: "1px solid #ddd", borderRadius: 12, padding: 16, marginBottom: 16 }}>
      <div style={{ fontWeight: 700, marginBottom: 12 }}>{title}</div>
      {children}
    </div>
  );
}

export default function App() {
  // Auth
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState(() => localStorage.getItem("jwt") || "");
  const jwtPayload = useMemo(() => (token ? decodeJwt(token) : null), [token]);

  // If your backend issues a claim like {"role":"admin"} or {"is_admin":true}, use it here.
  const isAdmin = Boolean(jwtPayload?.role === "admin" || jwtPayload?.is_admin === true);

  // WS state
  const wsRef = useRef(null);
  const [wsStatus, setWsStatus] = useState("disconnected");
  const [wsError, setWsError] = useState("");
  const [inbox, setInbox] = useState([]); // {from, plaintext, raw}
  const [rawFrames, setRawFrames] = useState([]); // admin debug: raw frames
  const [toUser, setToUser] = useState("");
  const [message, setMessage] = useState("");

  // Debug instrumentation (admin-only view)
  const [lastSent, setLastSent] = useState(null);
  const [lastReceived, setLastReceived] = useState(null);
  const [pingMs, setPingMs] = useState(null);

  useEffect(() => {
    if (token) localStorage.setItem("jwt", token);
    else localStorage.removeItem("jwt");
  }, [token]);

  async function login() {
    setWsError("");
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (!res.ok) {
      const err = await safeJson(res);
      throw new Error(err?.detail || "Login failed");
    }

    const data = await res.json();
    setToken(data.access_token);
  }

  function logout() {
    disconnectWs();
    setToken("");
    setInbox([]);
    setRawFrames([]);
    setLastSent(null);
    setLastReceived(null);
    setPingMs(null);
  }

  function connectWs() {
    setWsError("");
    if (!token) {
      setWsError("Login required before connecting.");
      return;
    }
    if (wsRef.current) return;

    const ws = new WebSocket(`${WS_BASE}?token=${encodeURIComponent(token)}`);
    wsRef.current = ws;
    setWsStatus("connecting");

    ws.onopen = () => setWsStatus("connected");
    ws.onclose = () => {
      wsRef.current = null;
      setWsStatus("disconnected");
    };
    ws.onerror = () => setWsError("WebSocket error (check server and token).");

    ws.onmessage = (evt) => {
      const raw = evt.data;
      let data;
      try {
        data = JSON.parse(raw);
      } catch {
        data = { type: "unknown", raw };
      }

      setLastReceived(data);
      // Keep last N raw frames for admin debugging
      setRawFrames((prev) => [data, ...prev].slice(0, 50));

      if (data.type === "message") {
        const plaintext = decryptFromSender(data.ciphertext);
        setInbox((prev) => [
          {
            from: data.from,
            to: data.to,
            plaintext,
            raw: data,
            ts: new Date().toISOString(),
          },
          ...prev,
        ]);
      }
      if (data.type === "pong" && typeof data._t0 === "number") {
        setPingMs(Date.now() - data._t0);
      }
    };
  }

  function disconnectWs() {
    const ws = wsRef.current;
    if (ws) {
      ws.close();
      wsRef.current = null;
    }
  }

  function sendMessage() {
    setWsError("");
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      setWsError("WebSocket not connected.");
      return;
    }
    if (!toUser.trim()) {
      setWsError("Recipient required.");
      return;
    }
    if (!message.trim()) {
      setWsError("Message required.");
      return;
    }

    // Encrypt client-side (placeholder)
    const ciphertext = encryptForRecipient(message.trim());
    const envelope = {
      type: "send",
      to: toUser.trim(),
      ciphertext,
      nonce: "client-generated-nonce", // replace with real nonce for real crypto
      algo: "placeholder-base64",       // replace with real algo label
      msg_id: crypto.randomUUID?.() || String(Date.now()),
    };

    ws.send(JSON.stringify(envelope));
    setLastSent(envelope);
    setMessage("");
  }

  function ping() {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    // We can embed a timestamp to measure RTT in UI; server can just respond with pong
    const payload = { type: "ping", _t0: Date.now() };
    ws.send(JSON.stringify(payload));
  }

  // Optional admin-only: call backend debug endpoint (backend must enforce admin)
  async function adminDebugSnapshot() {
    const res = await fetch(`${API_BASE}/admin/debug`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      const err = await safeJson(res);
      throw new Error(err?.detail || "Admin debug request failed");
    }
    return res.json();
  }

  return (
    <div style={{ maxWidth: 980, margin: "30px auto", padding: "0 16px", fontFamily: "system-ui, sans-serif" }}>
      <h1 style={{ marginBottom: 8 }}>Secure Messaging (FastAPI + WebSocket)</h1>
      <div style={{ color: "#555", marginBottom: 18 }}>
        Client-side encrypted messaging flow with an admin-only debugging panel (backend enforced).
      </div>

      <Section title="Authentication">
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
          <input
            style={inputStyle}
            placeholder="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={Boolean(token)}
          />
          <input
            style={inputStyle}
            placeholder="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={Boolean(token)}
          />
          {!token ? (
            <button style={btnStyle} onClick={() => login().catch((e) => setWsError(e.message))}>
              Login
            </button>
          ) : (
            <button style={btnStyle} onClick={logout}>
              Logout
            </button>
          )}
        </div>

        <div style={{ marginTop: 10, fontSize: 13, color: "#444" }}>
          <div>JWT present: <b>{token ? "Yes" : "No"}</b></div>
          <div>Role (from token): <b>{isAdmin ? "admin" : "user/unknown"}</b></div>
        </div>

        {wsError ? <div style={{ marginTop: 10, color: "crimson" }}>{wsError}</div> : null}
      </Section>

      <Section title="WebSocket Connection">
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <div>Status: <b>{wsStatus}</b></div>
          <button style={btnStyle} onClick={connectWs} disabled={!token || wsStatus !== "disconnected"}>
            Connect
          </button>
          <button style={btnStyle} onClick={disconnectWs} disabled={wsStatus !== "connected"}>
            Disconnect
          </button>
          <button style={btnStyle} onClick={ping} disabled={wsStatus !== "connected"}>
            Ping
          </button>
          {pingMs !== null && <div>RTT: <b>{pingMs} ms</b></div>}
        </div>
      </Section>

      <Section title="Send Message">
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
          <input
            style={inputStyle}
            placeholder="recipient username"
            value={toUser}
            onChange={(e) => setToUser(e.target.value)}
          />
          <input
            style={{ ...inputStyle, flex: 1, minWidth: 260 }}
            placeholder="message (encrypted client-side)"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
          <button style={btnStyle} onClick={sendMessage} disabled={wsStatus !== "connected"}>
            Send
          </button>
        </div>
        <div style={{ marginTop: 10, fontSize: 12, color: "#666" }}>
          Note: Encryption is a placeholder in this demo. Replace encrypt/decrypt with real E2EE.
        </div>
      </Section>

      <Section title="Inbox">
        {inbox.length === 0 ? (
          <div style={{ color: "#666" }}>No messages received yet.</div>
        ) : (
          <div style={{ display: "grid", gap: 10 }}>
            {inbox.map((m, idx) => (
              <div key={idx} style={{ border: "1px solid #eee", borderRadius: 12, padding: 12 }}>
                <div style={{ fontWeight: 700 }}>
                  From: {m.from} → To: {m.to}
                </div>
                <div style={{ marginTop: 6 }}>{m.plaintext}</div>
                <div style={{ marginTop: 8, fontSize: 12, color: "#777" }}>{m.ts}</div>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* ADMIN ONLY DEBUG PANEL */}
      {isAdmin && (
        <Section title="Admin Debug Panel">
          <div style={{ fontSize: 13, color: "#444", marginBottom: 10 }}>
            Visible only when JWT includes an admin claim. Backend must enforce admin on any privileged endpoints.
          </div>

          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button
              style={btnStyle}
              onClick={() => {
                setInbox([]);
                setRawFrames([]);
                setLastSent(null);
                setLastReceived(null);
                setPingMs(null);
              }}
            >
              Clear Debug State
            </button>

            <button
              style={btnStyle}
              onClick={() =>
                adminDebugSnapshot()
                  .then((data) => {
                    // Store snapshot as a "received" debug frame
                    setRawFrames((prev) => [{ type: "admin_debug_snapshot", data }, ...prev].slice(0, 50));
                  })
                  .catch((e) => setWsError(e.message))
              }
              disabled={!token}
            >
              Fetch /admin/debug
            </button>
          </div>

          <div style={{ marginTop: 12, display: "grid", gap: 12 }}>
            <DebugKV label="WS status" value={wsStatus} />
            <DebugKV label="Last sent envelope" value={lastSent} />
            <DebugKV label="Last received frame" value={lastReceived} />
            <DebugKV label="Recent raw frames (max 50)" value={rawFrames} />
          </div>
        </Section>
      )}
    </div>
  );
}

function DebugKV({ label, value }) {
  return (
    <div style={{ border: "1px solid #eee", borderRadius: 12, padding: 12 }}>
      <div style={{ fontWeight: 700, marginBottom: 8 }}>{label}</div>
      <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word", fontSize: 12, color: "#333" }}>
        {typeof value === "string" ? value : JSON.stringify(value, null, 2)}
      </pre>
    </div>
  );
}

async function safeJson(res) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

const inputStyle = {
  padding: "10px 12px",
  borderRadius: 10,
  border: "1px solid #ccc",
  minWidth: 220,
  outline: "none",
};

const btnStyle = {
  padding: "10px 14px",
  borderRadius: 10,
  border: "1px solid #ccc",
  background: "white",
  cursor: "pointer",
};
