"""Modbus TCP simulator.

HR[addr] = addr * 10 (FC3 read holding registers)
IR[addr] = 1000 + addr (FC4 read input registers)
Coils[addr] = addr % 2 (FC1 read coils)
DI[addr] = 1 if addr % 3 == 0 else 0 (FC2 read discrete inputs)

Expected output with 'Read Holding Registers 0:10':
  HR40001=0, HR40002=10, HR40003=20, HR40004=30, ...
"""
import argparse
import asyncio
import logging
import os

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartAsyncTcpServer

COUNT = 200

hr_values = [i * 10 for i in range(COUNT)]
ir_values = [1000 + i for i in range(COUNT)]
co_values = [i % 2 for i in range(COUNT)]
di_values = [1 if i % 3 == 0 else 0 for i in range(COUNT)]

store = ModbusSlaveContext(
    di=ModbusSequentialDataBlock(0, di_values),
    co=ModbusSequentialDataBlock(0, co_values),
    hr=ModbusSequentialDataBlock(0, hr_values),
    ir=ModbusSequentialDataBlock(0, ir_values),
    zero_mode=True,
)
ctx = ModbusServerContext(slaves=store, single=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Modbus TCP simulator")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SCADAVER_MODBUS_PORT", "502")),
        help="TCP port to listen on (default: 502 or SCADAVER_MODBUS_PORT)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SCADAVER_SIM_HOST", "0.0.0.0"),
        help="IP address to bind (default: 0.0.0.0 or SCADAVER_SIM_HOST)",
    )
    return parser.parse_args()


async def main() -> None:
    logging.getLogger("pymodbus").setLevel(logging.CRITICAL)
    args = parse_args()
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be between 1 and 65535")

    print(f"Modbus TCP simulator listening on {args.host}:{args.port}")
    print(f"  HR[0..{COUNT-1}]: value = addr * 10  (display 40001+addr)")
    print(f"  IR[0..{COUNT-1}]: value = 1000 + addr (display 30001+addr)")
    print(f"  Coils[0..{COUNT-1}]: alternating 0/1")
    print(f"  DI[0..{COUNT-1}]: ON every 3rd address")
    await StartAsyncTcpServer(context=ctx, address=(args.host, args.port))


asyncio.run(main())
