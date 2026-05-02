from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Set

from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles

from .auth import SessionStore
from .core.simulator import FleetSimulator


class ConnectionHub:
    def __init__(self) -> None:
        self.connections: Set[WebSocket] = set()
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self.lock:
            self.connections.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self.lock:
            self.connections.discard(websocket)

    async def broadcast(self, payload: Any) -> None:
        stale = []
        async with self.lock:
            conns = list(self.connections)
        for ws in conns:
            try:
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)
        if stale:
            async with self.lock:
                for ws in stale:
                    self.connections.discard(ws)


def get_simulator(app: FastAPI) -> FleetSimulator:
    return app.state.simulator


def get_hub(app: FastAPI) -> ConnectionHub:
    return app.state.hub


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.sessions = SessionStore()
    app.state.simulator = FleetSimulator()
    app.state.hub = ConnectionHub()

    async def loop():
        while True:
            app.state.simulator.tick()
            await app.state.hub.broadcast(app.state.simulator.snapshot())
            await asyncio.sleep(0.5)

    task = asyncio.create_task(loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="PuppySecOps Platform", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "static")), name="static")

from .routes import router  # noqa: E402

app.include_router(router)
