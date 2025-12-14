import React, { useEffect, useMemo, useRef, useState } from "react";

/**
 * CONFIG (Minecraft-LAN style)
 */
const SERVER_HOST = window.location.hostname;
const API_BASE = `http://${SERVER_HOST}:8000`;
const WS_BASE = `ws://${SERVER_HOST}:8000/ws`;

function decodeJwt(token) {
  try {
    const [, payloadB64] = token.split(".");
    const json = atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function Section({ title, children }) {
  return (
    <div style={{ border: "1px solid #333", borderRadius: 12, padding: 16, marginBottom: 16 }}>
      <div style={{ fontWeight: 700, marginBottom: 12 }}>{title}</div>
      {children}
    </div>
  );
}

export default function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState(() => localStorage.getItem("jwt") || "");
  const jwtPayload = useMemo(() => (token ? decodeJwt(token) : null), [token]);
  const isAdmin = Boolean(jwtPayload?.role === "admin" || jwtPayload?.is_admin);

  const wsRef = useRef(null);
  const [wsStatus, setWsStatus] = useState("disconnected");
  const [wsError, setWsError] = useState("");

  useEffect(() => {
    if (token) localStorage.setItem("jwt", token);
    else localStorage.removeItem("jwt");
  }, [token]);

  async function register() {
    const body = new URLSearchParams({ username, password });
    const res = await fetch(`${API_BASE}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!res.ok) throw new Error((await res.json())?.detail || "Register failed");
  }

  async function login() {
    const body = new URLSearchParams({ username, password });
    const res = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!res.ok) throw new Error((await res.json())?.detail || "Login failed");
    const data = await res.json();
    setToken(data.access_token);
  }

  return (
    <div style={{ maxWidth: 960, margin: "30px auto", padding: 16, fontFamily: "monospace" }}>
      {/* 🔴 BUILD STAMP — MUST BE VISIBLE */}
      <div style={{ color: "red", fontWeight: 900, fontSize: 18, marginBottom: 16 }}>
        BUILD STAMP: APPJSX-LAN-LOGIN-01
      </div>

      <h1>Secure Messaging (LAN)</h1>

      <Section title="Auth">
        <input value={username} onChange={e => setUsername(e.target.value)} placeholder="username" />
        <input value={password} onChange={e => setPassword(e.target.value)} placeholder="password" type="password" />

        {!token ? (
          <>
            <button
              onClick={() =>
                login().catch(e => {
                  console.error(e);
                  setWsError(`LOGIN ERROR: ${e.message}`);
                })
              }
            >
              Login
            </button>

            <button
              onClick={() =>
                register().catch(e => {
                  console.error(e);
                  setWsError(`REGISTER ERROR: ${e.message}`);
                })
              }
            >
              Register
            </button>
          </>
        ) : (
          <button onClick={() => setToken("")}>Logout</button>
        )}

        {wsError && <div style={{ color: "crimson", marginTop: 10 }}>{wsError}</div>}
      </Section>

      <Section title="Debug">
        <div>Frontend host: {SERVER_HOST}</div>
        <div>API: {API_BASE}</div>
        <div>WS: {WS_BASE}</div>
        <div>JWT present: {token ? "YES" : "NO"}</div>
        <div>Admin: {isAdmin ? "YES" : "NO"}</div>
      </Section>
    </div>
  );
}
