"""bacpypes3 BACnet/IP simulator for CI integration tests.

Runs as a BACnet device on UDP 47808 (0xBAC0).
Responds to Who-Is with I-Am, and to ReadProperty for object-name.
"""
import asyncio
import bacpypes3
from bacpypes3.primitivedata import Real, Unsigned, CharacterString
from bacpypes3.basetypes import PropertyIdentifier
from bacpypes3.app import Application


async def main():
    app = await Application.create(
        "bacpypes3",
        {
            "object-name": "ScadaverCI",
            "object-type": "device",
            "object-identifier": ("device", 1000),
            "vendor-identifier": 999,
            "vendor-name": "scadaver-sim",
            "model-name": "CI-BACnet-Sim",
            "firmware-revision": "1.0",
            "application-software-version": "1.0",
            "protocol-version": 1,
            "protocol-revision": 14,
            "max-apdu-length-accepted": 1476,
        },
    )
    await asyncio.get_event_loop().run_until_complete(asyncio.sleep(3600))


if __name__ == "__main__":
    asyncio.run(main())
