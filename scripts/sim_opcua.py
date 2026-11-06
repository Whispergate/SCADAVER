"""asyncua OPC-UA server for CI integration tests.

Listens on TCP port 4840 with no-security endpoint.
"""
# Accuracy audit (2026-08): OPC UA CI protocol fixture, not a production UA
# server. Sources: OPC UA Part 4 services
# (https://reference.opcfoundation.org/specs/OPC-10000-4/full) and Part 6
# UA-TCP mappings (https://reference.opcfoundation.org/Core/Part6/v105/docs/).
# Surface: no-security endpoint and a deterministic writable variable.
import argparse
import asyncio
import os
from asyncua import Server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SCADAver CI OPC UA simulator")
    parser.add_argument("--host", default=os.environ.get("SCADAVER_SIM_HOST", "127.0.0.1"))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SCADAVER_OPCUA_PORT", "4840")),
    )
    return parser.parse_args()


async def main():
    args = parse_args()
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be between 1 and 65535")
    server = Server()
    await server.init()
    server.set_endpoint(f"opc.tcp://{args.host}:{args.port}/freeopcua/server/")
    server.set_server_name("ScadaverCI OPC-UA Server")

    uri = "urn:scadaver:ci:server"
    idx = await server.register_namespace(uri)

    objects = server.get_objects_node()
    obj = await objects.add_object(idx, "CIDevice")
    tag = await obj.add_variable(idx, "Tag1", 42.0)
    await tag.set_writable()

    async with server:
        while True:
            await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())
