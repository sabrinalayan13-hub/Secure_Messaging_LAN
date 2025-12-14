from fastapi import WebSocket
from typing import Dict


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, username: str, websocket: WebSocket):
        # Reject duplicate logins for same username
        if username in self.active_connections:
            await self.active_connections[username].close(code=1008)
            self.active_connections.pop(username, None)

        await websocket.accept()
        self.active_connections[username] = websocket

        # Notify others
        await self.broadcast(f"[SYSTEM] {username} joined the channel.")

    def disconnect(self, username: str):
        if username in self.active_connections:
            self.active_connections.pop(username, None)

    async def send_personal_message(self, message: str, username: str):
        ws = self.active_connections.get(username)
        if ws:
            await ws.send_text(message)
            return True
        return False

    async def broadcast(self, message: str):
        for ws in list(self.active_connections.values()):
            await ws.send_text(message)

    async def notify_user_not_found(self, sender: str, recipient: str):
        ws = self.active_connections.get(sender)
        if ws:
            await ws.send_text(f"[SYSTEM] User '{recipient}' is not online.")

    def list_users(self):
        return list(self.active_connections.keys())


manager = ConnectionManager()
