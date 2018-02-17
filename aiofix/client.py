import argparse
import asyncio
import logging

from aiofix.engine_streams import StreamFIXConnection, StreamFIXSession, BaseMonitor
from aiofix.FIXValidator import FIX44Validator


class TestStreamFIXSession(StreamFIXSession):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        validator = FIX44Validator()
        components = [(49, self.username), (56, 'SERVER')]
        super().__init__(44, validator, components, logger=None)

    def embellish_logon(self, builder):
        builder.append(553, self.username)
        builder.append(554, self.password)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Connect as fix client')
    parser.add_argument('--host', default='localhost')
    parser.add_argument('--port', type=int, default=8888)
    parser.add_argument('--username', type=str, default="hello")
    parser.add_argument('--password', type=str, default="world")
    parser.add_argument('--debug', action='store_true', default=False)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    loop = asyncio.get_event_loop()

    async def connect():
        reader, writer = await asyncio.open_connection(host=args.host, port=args.port, loop=loop)
        session = TestStreamFIXSession(username=args.username, password=args.password)
        fixconnection = StreamFIXConnection(reader, writer, monitor=BaseMonitor(), session=session)
        await fixconnection.read_loop()

    try:
        loop.run_until_complete(connect())
    except KeyboardInterrupt:
        pass

    loop.close()
