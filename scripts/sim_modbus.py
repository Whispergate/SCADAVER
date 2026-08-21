"""pymodbus async TCP server on port 5020 for CI integration tests.

Compatible with pymodbus 3.x.
"""
import asyncio
from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)

try:
    from pymodbus.device import ModbusDeviceIdentification
    _identity = ModbusDeviceIdentification(
        info_name={
            "VendorName": "scadaver-sim",
            "ProductCode": "SIM-MODBUS",
            "VendorUrl": "https://github.com/scadaver",
            "ProductName": "Modbus CI Simulator",
            "ModelName": "SIM-1",
            "MajorMinorRevision": "1.0",
        }
    )
except Exception:
    _identity = None


async def main():
    datablock = ModbusSequentialDataBlock(0, [i % 65536 for i in range(1000)])
    store = ModbusSlaveContext(
        co=ModbusSequentialDataBlock(0, [0] * 1000),
        di=ModbusSequentialDataBlock(0, [0] * 1000),
        hr=datablock,
        ir=datablock,
    )
    context = ModbusServerContext(slaves=store, single=True)
    await StartAsyncTcpServer(
        context=context,
        identity=_identity,
        address=("0.0.0.0", 5020),
    )


if __name__ == "__main__":
    asyncio.run(main())
