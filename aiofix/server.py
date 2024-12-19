import argparse
import asyncio
import logging

from aiofix.engine_streams import (
    BaseApplication,
    BaseMonitor,
    LoginError,
    StreamFIXSession,
)


class TestApplication(BaseApplication):
    async def check_credentials_create_session(self, data, kwargs):
        if data["username"] == "hello" and data["password"] == "world":
            return StreamFIXSession(**kwargs)
        raise LoginError("Incorrect login")


async def main():
    application = TestApplication()
    monitor = BaseMonitor()
    application.monitor = monitor
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
