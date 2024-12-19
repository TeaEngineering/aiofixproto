aiofixproto
----
This is a toy FIX protocol server/client used to test various other systems over the years.

In particular the server component can deliver precise Rejects/BusinessMessageRejects for malformed custom messages with little extra code.

    $ pip install aiofixproto
    $ python -m aiofix.server &
    INFO:root:Serving on ('127.0.0.1', 8888)
    ...
    INFO:fix-1-127.0.0.1:49516:Socket connected
    INFO:fix-1-127.0.0.1:49516:post_login (server) reached - hb_interval=5

    $ python -m aiofix.client
    INFO:fix-1-127.0.0.1:8888:post_connect (client) reached - hb_interval=5
    INFO:fix-1-127.0.0.1:8888:Socket connected


Supported FIX versions
----
* FIX42
* FIX44
