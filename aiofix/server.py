import argparse
import asyncio
import logging
from typing import Any

from aiofix.engine_streams import (
    BaseApplication,
)


class TestApplication(BaseApplication):
    async def check_credentials(self, data: dict[str, Any]) -> bool:
        if data["username"] == "hello":
            if data["password"] == "world":
                return True
        return False


async def main() -> None:
    application = TestApplication()
    server = await asyncio.start_server(
        application.handle_stream_pair, "127.0.0.1", 8888
    )

    # Serve requests until Ctrl+C is pressed
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    logging.info(f"Serving on {addrs}")
    async with server:
        await server.serve_forever()

    # Close the server
    server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connect as fix client")
    parser.add_argument("--debug", action="store_true", default=False)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    asyncio.run(main())
