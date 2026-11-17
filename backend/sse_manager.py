import asyncio
import json


class SSEManager:
    def __init__(self):
        self.clients = set()

    async def connect(self):
        queue = asyncio.Queue()
        self.clients.add(queue)
        return queue

    def disconnect(self, queue):
        self.clients.discard(queue)

    async def broadcast(self, event_data: dict):
        message = json.dumps(event_data)

        for queue in list(self.clients):
            await queue.put(message)


sse_manager = SSEManager()