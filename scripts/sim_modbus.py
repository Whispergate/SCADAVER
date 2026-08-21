"""pymodbus TCP server on port 5020 for CI integration tests.

Supports pymodbus 2.x, 3.x, and 3.5+ (new ModbusTcpServer API).
"""
import asyncio
import sys


async def main():
    from pymodbus.datastore import (
        ModbusSequentialDataBlock,
        ModbusServerContext,
        ModbusSlaveContext,
    )

    store = ModbusSlaveContext(
        co=ModbusSequentialDataBlock(0, [0] * 1000),
        di=ModbusSequentialDataBlock(0, [0] * 1000),
        hr=ModbusSequentialDataBlock(0, list(range(1000))),
        ir=ModbusSequentialDataBlock(0, list(range(1000))),
    )
    context = ModbusServerContext(slaves=store, single=True)

    # Try new pymodbus 3.5+ API first
    try:
        from pymodbus.server import ModbusTcpServer
        print("sim_modbus: using ModbusTcpServer (pymodbus 3.5+)", flush=True)
        server = ModbusTcpServer(context=context, address=("0.0.0.0", 5020))
        await server.serve_forever()
        return
    except (ImportError, AttributeError, TypeError):
        pass

    # Fall back to StartAsyncTcpServer (pymodbus 2.x / early 3.x)
    from pymodbus.server import StartAsyncTcpServer
    print("sim_modbus: using StartAsyncTcpServer (legacy API)", flush=True)
    await StartAsyncTcpServer(context=context, address=("0.0.0.0", 5020))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:
        print(f"sim_modbus FATAL: {exc}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)
