from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from jose import jwt, JWTError

from database import engine, SessionLocal
from model import Base, User
import auth
import websocket as ws

app = FastAPI()
Base.metadata.create_all(bind=engine)

# =========================================================
# CORS — LAN dev (explicit origins; safe with credentials)
# =========================================================
# IMPORTANT:
# - Add your server LAN IP below (the one shown by Vite "Network:")
# - You can add additional LAN IPs later if your IP changes
LAN_IP = "192.168.0.158"  # <-- update if your server IP changes

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        f"http://{LAN_IP}:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"ok": True}

# =========================================================
# Auth routes (with diagnostics)
# =========================================================
@app.post("/register")
def register(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(auth.get_db),
    request: Request = None,
):
    # Diagnostics (prints to backend console)
    try:
        print(
            "[REGISTER]",
            "client=", request.client.host if request else None,
            "origin=", request.headers.get("origin") if request else None,
            "host=", request.headers.get("host") if request else None,
        )
    except Exception:
        pass

    if db.query(User).filter(User.username == form_data.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")

    # Enforce password policy
    auth.validate_password_or_raise(form_data.password)

    hashed = auth.hash_password(form_data.password)
    new_user = User(username=form_data.username, hashed_password=hashed)
    db.add(new_user)
    db.commit()
    return {"msg": "User registered successfully"}


@app.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(auth.get_db),
    request: Request = None,
):
    # Diagnostics (prints to backend console)
    try:
        print(
            "[LOGIN]",
            "client=", request.client.host if request else None,
            "origin=", request.headers.get("origin") if request else None,
            "host=", request.headers.get("host") if request else None,
        )
    except Exception:
        pass

    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    token = auth.create_access_token(subject=user.username)
    return {"access_token": token, "token_type": "bearer"}

# =========================================================
# WebSocket (token-secured) + diagnostics
# =========================================================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Secure websocket:
      ws://<server-ip>:8000/ws?token=<JWT>

    Message formats:
      - Broadcast: "hello everyone"
      - DM:        "recipient:message"
      - Command:   "/users" -> list online users
    """

    # Diagnostics: show connection attempt source
    try:
        print(
            "[WS CONNECT ATTEMPT]",
            "client=", websocket.client.host if websocket.client else None,
            "path=", str(websocket.url),
        )
    except Exception:
        pass

    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return

    # Validate token and extract username
    try:
        payload = jwt.decode(
            token,
            auth.SECRET_KEY,
            algorithms=[auth.ALGORITHM],
            issuer=auth.JWT_ISSUER,
            audience=auth.JWT_AUDIENCE,
            options={"require_sub": True, "require_exp": True},
        )
        username = payload.get("sub")
        if not username:
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return

    # Ensure user still exists in DB
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            await websocket.close(code=1008)
            return
    finally:
        db.close()

    # Connect (accept + join broadcast handled by manager)
    await ws.manager.connect(username, websocket)

    # Confirm to connecting user
    await ws.manager.send_personal_message(
        "[SYSTEM] Connected. DM: recipient:message | Broadcast: plain text | /users for online list",
        username,
    )

    try:
        while True:
            data = (await websocket.receive_text()).strip()
            if not data:
                continue

            # Commands
            if data.lower() == "/users":
                users = ws.manager.list_users()
                await ws.manager.send_personal_message(
                    "[SYSTEM] Online: " + (", ".join(users) if users else "(none)"),
                    username,
                )
                continue

            # Direct message format: "recipient:message"
            if ":" in data:
                recipient, message = data.split(":", 1)
                recipient = recipient.strip()
                message = message.strip()

                if not recipient or not message:
                    await ws.manager.send_personal_message(
                        "[SYSTEM] Invalid format. Use: recipient:message",
                        username,
                    )
                    continue

                delivered = await ws.manager.send_personal_message(
                    f"{username}: {message}",
                    recipient,
                )
                if not delivered:
                    await ws.manager.notify_user_not_found(username, recipient)

            else:
                # Broadcast
                await ws.manager.broadcast(f"{username}: {data}")

    except WebSocketDisconnect:
        ws.manager.disconnect(username)
        await ws.manager.broadcast(f"[SYSTEM] {username} left the channel.")
    except Exception as e:
        ws.manager.disconnect(username)
        try:
            print("[WS ERROR]", repr(e))
        except Exception:
            pass
        try:
            await ws.manager.broadcast(f"[SYSTEM] {username} disconnected unexpectedly.")
        except Exception:
            pass
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
