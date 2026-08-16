"""MQTT 3.1.1 broker simulator using amqtt.

Anonymous access enabled, $SYS topics published every 5 s (retained),
no ACL restrictions.
"""
import argparse
import asyncio
import logging
import os

from amqtt.broker import Broker


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MQTT broker simulator")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SCADAVER_MQTT_PORT", "1883")),
        help="TCP port to listen on (default: 1883 or SCADAVER_MQTT_PORT)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SCADAVER_SIM_HOST", "0.0.0.0"),
        help="IP address to bind (default: 0.0.0.0 or SCADAVER_SIM_HOST)",
    )
    return parser.parse_args()


async def main() -> None:
    logging.getLogger("amqtt").setLevel(logging.CRITICAL)
    logging.getLogger("transitions").setLevel(logging.CRITICAL)
    args = parse_args()
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be between 1 and 65535")

    config = {
        "listeners": {
            "default": {
                "type": "tcp",
                "bind": f"{args.host}:{args.port}",
                "max-connections": 50,
            },
        },
        "sys_interval": 5,
        "auth": {
            "allow-anonymous": True,
        },
        "topic-check": {
            "enabled": False,
        },
    }

    broker = Broker(config=config)
    await broker.start()

    target = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    print(f"MQTT broker simulator listening on {args.host}:{args.port}")
    print(f"  anonymous access: enabled")
    print(f"  $SYS topics: published every 5 s (retained)")
    print()
    print("MQTT learning commands (mosquitto-clients required):")
    print()
    print(f"  Subscribe everything (open in a separate terminal):")
    print(f"    mosquitto_sub -h {target} -p {args.port} -t '#' -v")
    print()
    print(f"  Subscribe $SYS for broker fingerprint:")
    print(f"    mosquitto_sub -h {target} -p {args.port} -t '$SYS/#' -v")
    print()
    print(f"  Publish a message:")
    print(f"    mosquitto_pub -h {target} -p {args.port} -t test/hello -m world")
    print()
    print(f"  Subscribe Sparkplug B ICS topics:")
    print(f"    mosquitto_sub -h {target} -p {args.port} -t 'spBv1.0/#' -v")
    print()
    print(f"  scadaver probe:")
    print(f"    scadaver -i {target} -p {args.port} --protocol mqtt scan")
    print()
    print(f"  scadaver interactive shell:")
    print(f"    scadaver mqtt --host {target} --port {args.port}")
    print()
    print(f"  Integration tests:")
    print(f"    $env:TEST_MQTT_HOST=\"{target}\"; cargo test --test mqtt_integration")
    print()

    try:
        await asyncio.Future()
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        await broker.shutdown()


asyncio.run(main())
