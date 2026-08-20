"""Minimal pysnmp UDP agent on port 16100 for CI integration tests.

Responds to SNMPv2c community 'public' GET requests for sysDescr.0.
"""
import asyncio
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.api import v2c

TARGET_PORT = 16100
COMMUNITY = b"public"
SYS_DESCR_OID = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYS_DESCR_VALUE = b"scadaver CI SNMP Simulator"


async def main():
    snmp_engine = engine.SnmpEngine()

    config.addTransport(
        snmp_engine,
        udp.domainName,
        udp.UdpTransport().openServerMode(("0.0.0.0", TARGET_PORT)),
    )

    config.addV1System(snmp_engine, "my-area", COMMUNITY)
    config.addVacmUser(
        snmp_engine, 2, "my-area", "noAuthNoPriv",
        (1, 3, 6), (1, 3, 6),
    )

    ctx = context.SnmpContext(snmp_engine)

    mibBuilder = ctx.getMibInstrum().getMibBuilder()
    mibBuilder.importSymbols("SNMPv2-MIB", "sysDescr")
    mibBuilder.importSymbols("SNMPv2-SMI", "Integer32")

    (sysDescr,) = mibBuilder.importSymbols("SNMPv2-MIB", "sysDescr")
    sysDescr = sysDescr.clone(SYS_DESCR_VALUE)

    mib_instrum = ctx.getMibInstrum()
    mib_instrum.writeVars(
        ((sysDescr.name + (0,), sysDescr.clone(SYS_DESCR_VALUE)),)
    )

    cmdrsp.GetCommandResponder(snmp_engine, ctx)
    cmdrsp.NextCommandResponder(snmp_engine, ctx)
    cmdrsp.BulkCommandResponder(snmp_engine, ctx)

    snmp_engine.transportDispatcher.jobStarted(1)
    try:
        snmp_engine.transportDispatcher.runDispatcher()
    finally:
        snmp_engine.transportDispatcher.closeDispatcher()


if __name__ == "__main__":
    asyncio.run(main())
