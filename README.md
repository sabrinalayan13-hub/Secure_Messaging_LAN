Secure Messaging LAN

Local-Network Secure Chat with Authenticated WebSockets

Overview

Secure Messaging LAN is a locally hosted, authentication-protected messaging system designed for secure communication within a single local network (LAN).
The system is intentionally not internet-facing and behaves similarly to Minecraft LAN discovery: users can only connect if they are on the same network as the server.

The application supports:

Account registration with strict password policy enforcement

JWT-based authenticated sessions

Real-time messaging via WebSockets

Zero message persistence (messages are never stored server-side)

Mobile and desktop access on the same network

Hardened authentication and token validation

This project demonstrates secure backend design, LAN-only service exposure, and real-time communication principles suitable for controlled environments.

Architecture
┌─────────────────────────────┐
│        Client (Browser)     │
│  HTML + Vanilla JS Terminal │
│  - Login / Register         │
│  - WebSocket Chat           │
└─────────────┬───────────────┘
              │ HTTP + WS (LAN only)
              ▼
┌─────────────────────────────┐
│        FastAPI Backend      │
│  - Auth (JWT)               │
│  - Password Hashing         │
│  - WebSocket Manager        │
│  - No Message Storage       │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│        SQLite Database      │
│  - User accounts only       │
│  - No message persistence   │
└─────────────────────────────┘

Key Design Principles
LAN-Only Access Model

Server binds to 0.0.0.0

Frontend dynamically targets window.location.hostname

Clients must be on the same local network

No cloud dependencies

No external APIs

Security-First Defaults

Passwords hashed using bcrypt-sha256

JWT secrets injected via environment variables

Strict password policy:

12–15 characters

At least one uppercase letter

At least one special character from an allowed set

JWT validation includes:

Expiration (exp)

Issuer (iss)

Audience (aud)

WebSocket connections require valid JWTs

No Message Retention

Messages are relayed in memory only

No server-side logs of message content

No chat history stored or recoverable

Database contains only user credentials

Programs & Technologies Used
Backend

Python 3.11+

FastAPI

Uvicorn (ASGI server)

SQLAlchemy

SQLite

python-jose (JWT handling)

passlib (bcrypt-sha256 hashing)

python-multipart (form handling)

WebSockets (ASGI)

Frontend

HTML5

Vanilla JavaScript

CSS (CRT-style terminal UI)

Vite (LAN-friendly dev server)

Development & Operations

Windows PowerShell / CMD

Batch scripts for start/stop

Local firewall rules for LAN testing

Mobile browser testing over Wi-Fi

Practical Applications

This system is suitable for environments where privacy, isolation, and simplicity are more important than global scalability.

Example Use Cases

Secure communication across an office building

Internal IT / SOC coordination

Incident response teams

Temporary secure networks (events, labs, field deployments)

Research or academic environments

Air-gapped or semi-isolated networks

Why This Works Well in Secure Environments

No cloud reliance

No third-party services

Easy to audit

Predictable network boundaries

Minimal attack surface

Can run entirely offline

Security Review (Technical)
Strengths

Strong password hashing (bcrypt-sha256)

JWT secrets not hard-coded

Token-secured WebSockets (prevents impersonation)

No message persistence

LAN-restricted connectivity

Minimal dependencies

Clear separation of auth vs messaging

Known Limitations (Intentional)

No end-to-end encryption (E2EE) implemented yet
(client-side crypto scaffolding is present)

No rate limiting (acceptable for trusted LANs)

No role-based access beyond basic admin hooks

SQLite chosen for simplicity, not high concurrency

These tradeoffs are intentional to keep the system auditable, understandable, and deployable in controlled networks.

Future Enhancements (Optional)

Client-side E2EE (X25519 + XChaCha20-Poly1305)

Hardware-backed key storage

Role-based authorization

Admin audit endpoints

TLS termination for wired networks

Message integrity verification

Network discovery / broadcast presence

Project Goals

This project was built to demonstrate:

Secure backend engineering

Real-time communication systems

Authentication hardening

LAN-only service design

Practical security tradeoffs

Debugging and deployment in real networks

It is intentionally not a consumer chat remember app—it is a controlled-environment communication system.

Disclaimer

This project is designed for trusted local networks.
If deployed beyond LAN or into hostile environments, additional hardening is required.
