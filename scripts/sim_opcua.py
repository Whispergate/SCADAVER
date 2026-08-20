"""asyncua OPC-UA server for CI integration tests.

Listens on TCP port 4840 with no-security endpoint.
"""
import asyncio
from asyncua import Server


async def main():
    server = Server()
    await server.init()
    server.set_endpoint("opc.tcp://0.0.0.0:4840/freeopcua/server/")
    server.set_server_name("ScadaverCI OPC-UA Server")
    server.set_security_policy([])

    uri = "urn:scadaver:ci:server"
    idx = await server.register_namespace(uri)

    objects = server.get_objects_node()
    obj = await objects.add_object(idx, "CIDevice")
    await obj.add_variable(idx, "Tag1", 42.0)

    async with server:
        while True:
            await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())
