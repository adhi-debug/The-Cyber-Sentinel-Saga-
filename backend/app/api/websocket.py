import asyncio
import contextlib
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.alerts import ALERTS_CHANNEL
from app.core.redis_manager import redis_manager

logger = logging.getLogger(__name__)

router = APIRouter()


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    """
    Stream real-time threat alerts to connected WebSocket clients.
    Each client gets its own Redis pubsub subscription.
    """
    await websocket.accept()

    redis = redis_manager.client
    if redis is None:
        await websocket.close(code=1011, reason="Redis not available")
        return

    pubsub = redis.pubsub()
    await pubsub.subscribe(ALERTS_CHANNEL)

    async def _relay() -> None:
        try:
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue

                await websocket.send_text(message["data"])

        except (WebSocketDisconnect, RuntimeError):
            logger.debug("Relay task stopped: websocket disconnected")

        except asyncio.CancelledError:
            raise

        except Exception:
            logger.exception("Unexpected error in relay task")

    async def _receive() -> None:
        try:
            while True:
                msg = await websocket.receive()

                if msg["type"] == "websocket.disconnect":
                    break

        except WebSocketDisconnect:
            logger.debug("Client disconnected")

        except RuntimeError:
            logger.debug("Receive called after disconnect")

        except asyncio.CancelledError:
            raise

        except Exception:
            logger.exception("Unexpected error in receive task")

    relay_task = asyncio.create_task(_relay())
    receive_task = asyncio.create_task(_receive())

    try:
        done, pending = await asyncio.wait(
            {relay_task, receive_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

        for task in pending:
            with contextlib.suppress(asyncio.CancelledError):
                await task

    finally:
        with contextlib.suppress(Exception):
            await pubsub.unsubscribe(ALERTS_CHANNEL)

        with contextlib.suppress(Exception):
            await pubsub.aclose()

        logger.debug("WebSocket client disconnected")