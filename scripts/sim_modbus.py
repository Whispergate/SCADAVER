"""pymodbus async TCP server on port 5020 for CI integration tests."""
import asyncio
from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification


def build_identity():
    identity = ModbusDeviceIdentification()
    identity.VendorName = "scadaver-sim"
    identity.ProductCode = "SIM-MODBUS"
    identity.VendorUrl = "https://github.com/scadaver"
    identity.ProductName = "Modbus CI Simulator"
    identity.ModelName = "SIM-1"
    identity.MajorMinorRevision = "1.0"
    return identity


async def main():
    store = ModbusSlaveContext(
        co=ModbusSequentialDataBlock(0, [0] * 100),
        di=ModbusSequentialDataBlock(0, [0] * 100),
        hr=ModbusSequentialDataBlock(0, [i % 65536 for i in range(200)]),
        ir=ModbusSequentialDataBlock(0, [i % 65536 for i in range(200)]),
    )
    context = ModbusServerContext(slaves=store, single=True)
    await StartAsyncTcpServer(
        context,
        identity=build_identity(),
        address=("0.0.0.0", 5020),
    )


if __name__ == "__main__":
    asyncio.run(main())
