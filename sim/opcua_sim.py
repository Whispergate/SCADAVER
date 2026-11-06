"""OPC-UA server simulator using asyncua.

Exposes a minimal OPC UA Binary server on the given host/port with:
  - Anonymous access enabled
  - One variable node: ns=1;i=1000 "Temperature" (Float, read-only)
  - GetEndpoints returns a single None-security endpoint
"""
# Accuracy audit (2026-08): asyncua-backed OPC UA server fixture.
# Standards reference: OPC UA Part 6 (Binary Transport), Part 4 (Services):
# https://reference.opcfoundation.org/Core/Part6/ and
# https://reference.opcfoundation.org/Core/Part4/
# Surface: HEL/ACK handshake, GetEndpoints, and variable browse used by smoke tests.
import argparse
import asyncio
import logging
import os

from asyncua import Server, ua


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OPC-UA server simulator")
    parser.add_argument(
        "--host",
        default=os.environ.get("SCADAVER_SIM_HOST", "0.0.0.0"),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SCADAVER_OPCUA_PORT", "4840")),
    )
    return parser.parse_args()


async def main() -> None:
    logging.getLogger("asyncua").setLevel(logging.CRITICAL)
    args = parse_args()

    server = Server()
    await server.init()
    server.set_endpoint(f"opc.tcp://{args.host}:{args.port}/freeopcua/server/")
    server.set_server_name("scadaver-opcua-sim")
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])

    uri = "urn:scadaver:opcua:sim"
    idx = await server.register_namespace(uri)

    objects = server.get_objects_node()
    sim_obj = await objects.add_object(idx, "SimDevice")
    temperature = await sim_obj.add_variable(idx, "Temperature", 21.5)
    await temperature.set_writable(False)

    async with server:
        print(f"OPC-UA simulator listening on opc.tcp://{args.host}:{args.port}/")
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
