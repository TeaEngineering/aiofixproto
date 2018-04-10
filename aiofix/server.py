import asyncio
import logging

from aiofix.engine_streams import BaseApplication, StreamFIXSession, StreamFIXConnection, BaseMonitor, LoginError


class TestApplication(BaseApplication):

    async def check_credentials_create_session(self, data, kwargs):
        if data['username'] == 'hello' and data['password'] == 'world':
            return StreamFIXSession(**kwargs)
        raise LoginError('Incorrect login')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    application = TestApplication()
    monitor = BaseMonitor()

    async def handle_stream_pair(reader, writer):
        fixconnection = StreamFIXConnection(reader, writer, monitor, application=application)
        await fixconnection.read_loop()

    loop = asyncio.get_event_loop()
    server = asyncio.start_server(handle_stream_pair, '127.0.0.1', 8888, loop=loop)
    server_task = loop.run_until_complete(server)

    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server_task.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server_task.wait_closed())
    loop.close()
