from fastapi import WebSocket
from typing import Dict


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, username: str, websocket: WebSocket):
        # Reject duplicate logins for same username
        if username in self.active_connections:
            try:
                await self.active_connections[username].close(code=1008)
            except Exception:
                pass
            self.active_connections.pop(username, None)

        await websocket.accept()
        self.active_connections[username] = websocket

        # Notify others
        await self.broadcast(f"[SYSTEM] {username} joined the channel.")

    def disconnect(self, username: str):
        self.active_connections.pop(username, None)

    async def send_personal_message(self, message: str, username: str) -> bool:
        ws = self.active_connections.get(username)
        if not ws:
            return False

        try:
            await ws.send_text(message)
            return True
        except Exception:
            # Socket likely dead; prune it
            self.active_connections.pop(username, None)
            return False

    async def broadcast(self, message: str):
        """
        Robust broadcast:
        - Sends to all connected clients
        - If any socket is dead, it removes it so future broadcasts keep working
        """
        dead_users = []

        for username, ws in self.active_connections.items():
            try:
                await ws.send_text(message)
            except Exception:
                dead_users.append(username)

        for username in dead_users:
            self.active_connections.pop(username, None)

    async def notify_user_not_found(self, sender: str, recipient: str):
        ws = self.active_connections.get(sender)
        if ws:
            try:
                await ws.send_text(f"[SYSTEM] User '{recipient}' is not online.")
            except Exception:
                self.active_connections.pop(sender, None)

    def list_users(self):
        return list(self.active_connections.keys())


manager = ConnectionManager()
