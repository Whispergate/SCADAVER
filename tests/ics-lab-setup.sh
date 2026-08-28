#!/usr/bin/env bash
# ICS/SCADA Protocol Lab — Kali Linux Setup
# Protocols: Modbus, S7Comm, BACnet, DNP3, OPC-UA, MQTT,
#            EtherNet/IP (CIP), IEC-104, SNMP, SLMP, FINS
#
# Usage: sudo bash ics-lab-setup.sh
#        sudo bash ics-lab-setup.sh --stop    (stop all containers)
#        sudo bash ics-lab-setup.sh --remove  (stop and remove everything)
set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────
NETWORK="ics-lab"
LAB_DIR="/opt/ics-lab"

# ── Colors ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()      { echo -e "  ${GREEN}✔${NC}  $*"; }
info()    { echo -e "  ${BLUE}→${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $*"; }
fail()    { echo -e "  ${RED}✘${NC}  $*"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}━━  $*${NC}"; }

# ── Root check ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "Run as root: sudo bash $0"

# ── CLI flags ──────────────────────────────────────────────────────────────────
ACTION="${1:-start}"
case "$ACTION" in
    --stop)
        section "Stopping all ICS lab containers"
        docker stop $(docker ps -q --filter name=ics-) 2>/dev/null && ok "All stopped" || warn "None running"
        exit 0
        ;;
    --remove)
        section "Removing all ICS lab containers and network"
        docker rm -f $(docker ps -aq --filter name=ics-) 2>/dev/null && ok "Containers removed" || warn "None found"
        docker network rm "$NETWORK" 2>/dev/null && ok "Network removed" || warn "Network not found"
        exit 0
        ;;
    --status)
        section "ICS lab container status"
        docker ps --filter name=ics- --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        exit 0
        ;;
    start) ;;
    *) fail "Unknown argument: $ACTION. Use --stop, --remove, or --status"; ;;
esac

# ── Banner ─────────────────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
echo "  ╦╔═╗╔═╗  ╦  ╔═╗╔╗ "
echo "  ║║  ╚═╗  ║  ╠═╣╠╩╗"
echo "  ╩╚═╝╚═╝  ╩═╝╩ ╩╚═╝  ICS/SCADA Protocol Lab"
echo -e "${NC}"

# ── Docker ─────────────────────────────────────────────────────────────────────
section "Docker"
if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    apt-get update -qq && apt-get install -y -qq docker.io
    systemctl enable docker --now
else
    ok "Docker $(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1)"
fi
if ! docker info &>/dev/null 2>&1; then
    info "Starting Docker daemon..."
    systemctl start docker
    sleep 3
fi
docker info &>/dev/null 2>&1 || fail "Docker daemon not responding"
ok "Docker daemon running"

# ── Network ────────────────────────────────────────────────────────────────────
section "Network"
if docker network ls --format '{{.Name}}' | grep -q "^${NETWORK}$"; then
    ok "Network '${NETWORK}' exists"
else
    docker network create --driver bridge "$NETWORK" >/dev/null
    ok "Created network '${NETWORK}'"
fi

# ── Helpers ────────────────────────────────────────────────────────────────────
pull_if_missing() {
    local image="$1"
    if docker image inspect "$image" &>/dev/null 2>&1; then
        ok "Cached: $image"
    else
        info "Pulling $image..."
        docker pull --quiet "$image" || { warn "Pull failed: $image"; return 1; }
        ok "Pulled: $image"
    fi
}

build_if_missing() {
    local tag="$1" context="$2"
    if docker image inspect "$tag" &>/dev/null 2>&1; then
        ok "Built: $tag"
    else
        info "Building $tag (may take a few minutes)..."
        docker build -t "$tag" "$context" -q >/dev/null \
            || { warn "Build failed: $tag — check: docker build $context -t $tag"; return 1; }
        ok "Built: $tag"
    fi
}

container_running() { docker ps --format '{{.Names}}' | grep -q "^$1$"; }
container_exists()  { docker ps -a --format '{{.Names}}' | grep -q "^$1$"; }

start_container() {
    local name="$1"; shift
    if container_running "$name"; then
        ok "Already running: $name"
    elif container_exists "$name"; then
        info "Restarting: $name"
        docker start "$name" >/dev/null
        ok "Restarted: $name"
    else
        info "Starting: $name"
        docker run -d --name "$name" --network "$NETWORK" --restart unless-stopped "$@" >/dev/null
        ok "Started: $name"
    fi
}

# ── Config files and Dockerfiles ───────────────────────────────────────────────
section "Config Files"
mkdir -p "$LAB_DIR"/{mosquitto,opcua,bacnet,iec104,dnp3,enip,slmp,fins}

# Mosquitto config
cat > "$LAB_DIR/mosquitto/mosquitto.conf" <<'EOF'
listener 1883
allow_anonymous true
persistence false
log_type error
EOF
ok "mosquitto.conf"

# ── OPC-UA server (asyncua) ────────────────────────────────────────────────────
cat > "$LAB_DIR/opcua/Dockerfile" <<'EOF'
FROM python:3.12-slim
RUN pip install --no-cache-dir asyncua==1.1.5
WORKDIR /app
COPY server.py .
CMD ["python", "-u", "server.py"]
EOF

cat > "$LAB_DIR/opcua/server.py" <<'PYEOF'
import asyncio, logging
from asyncua import Server

logging.basicConfig(level=logging.WARNING)

async def main():
    server = Server()
    await server.init()
    server.set_endpoint("opc.tcp://0.0.0.0:4840/")
    server.set_server_name("ICS Lab PLC Simulation")
    await server.set_build_info(
        product_uri="urn:ics:lab:plc",
        manufacturer_name="ICS Lab",
        product_name="Simulated PLC",
        software_version="1.0",
        build_number="1",
    )

    idx = await server.register_namespace("urn:ics:lab:simulator")
    objects = server.get_objects_node()

    plant = await objects.add_object(idx, "Plant")
    reactor  = await plant.add_object(idx, "Reactor")
    motor    = await plant.add_object(idx, "Motor")
    conveyor = await plant.add_object(idx, "Conveyor")

    # Reactor tags
    r_temp     = await reactor.add_variable(idx, "Temperature_C",    350.0)
    r_pressure = await reactor.add_variable(idx, "Pressure_Bar",     12.5)
    r_flow     = await reactor.add_variable(idx, "FlowRate_m3h",     8.3)
    r_status   = await reactor.add_variable(idx, "RunningStatus",    True)
    await r_temp.set_writable()
    await r_pressure.set_writable()

    # Motor tags
    m_rpm   = await motor.add_variable(idx, "RPM",          1450)
    m_amps  = await motor.add_variable(idx, "Current_A",    14.2)
    m_fault = await motor.add_variable(idx, "FaultCode",    0)
    await m_rpm.set_writable()

    # Conveyor tags
    c_speed   = await conveyor.add_variable(idx, "Speed_ms",     0.75)
    c_counter = await conveyor.add_variable(idx, "ItemCount",    10842)
    c_run     = await conveyor.add_variable(idx, "Running",      True)

    import math, time as t
    async with server:
        print("OPC-UA server running on opc.tcp://0.0.0.0:4840/", flush=True)
        tick = 0
        while True:
            await asyncio.sleep(2)
            tick += 1
            # Simulate slow oscillation on key values
            await r_temp.write_value(350.0 + 15.0 * math.sin(tick * 0.1))
            await r_pressure.write_value(12.5 + 1.2 * math.cos(tick * 0.07))
            await m_rpm.write_value(1450 + int(20 * math.sin(tick * 0.05)))
            await c_counter.write_value(10842 + tick * 3)

asyncio.run(main())
PYEOF
ok "OPC-UA simulator"

# ── BACnet/IP server (bacpypes3) ───────────────────────────────────────────────
cat > "$LAB_DIR/bacnet/Dockerfile" <<'EOF'
FROM python:3.12-slim
RUN pip install --no-cache-dir bacpypes3==0.0.102
WORKDIR /app
COPY server.py .
CMD ["python", "-u", "server.py"]
EOF

cat > "$LAB_DIR/bacnet/server.py" <<'PYEOF'
import asyncio, logging
from bacpypes3.settings import settings
from bacpypes3.app import Application
from bacpypes3.local.device import DeviceObject
from bacpypes3.local.analog import AnalogValueObject
from bacpypes3.local.binary import BinaryValueObject
from bacpypes3.pdu import Address

logging.basicConfig(level=logging.WARNING)
settings.DEBUG = []

async def main():
    device = DeviceObject(
        objectIdentifier=("device", 599),
        objectName="ICS-Lab-PLC",
        description="ICS Lab Simulated PLC",
        vendorIdentifier=999,
        vendorName="ICS Lab",
        modelName="SimPLC-1000",
        firmwareRevision="1.0",
        applicationSoftwareVersion="1.0",
        systemStatus="operational",
        segmentationSupported="noSegmentation",
        maxApduLengthAccepted=1024,
        apduSegmentTimeout=5000,
        apduTimeout=3000,
        numberOfApduRetries=3,
        maxMaster=127,
        maxInfoFrames=1,
    )

    app = Application.from_object_list(
        [device],
        local_address=Address("0.0.0.0"),
    )

    # Analog values with realistic engineering values
    points = [
        ("Reactor_Temperature", "degreesCelsius", 350.2, "operational"),
        ("Reactor_Pressure",    "pascals",        125000.0, "operational"),
        ("FlowRate_Inlet",      "litersPerSecond", 2.34, "operational"),
        ("Motor_Current",       "amperes",         14.7, "operational"),
        ("Tank_Level",          "percent",         68.4, "operational"),
    ]
    analog_objects = []
    for i, (name, units, val, status) in enumerate(points, start=1):
        obj = AnalogValueObject(
            objectIdentifier=("analogValue", i),
            objectName=name,
            presentValue=val,
            units=units,
            statusFlags=[False, False, False, False],
            outOfService=False,
        )
        app.add_object(obj)
        analog_objects.append((obj, val))

    # Binary values
    for i, (name, val) in enumerate([
        ("Pump_Running", True),
        ("Valve_Open",   True),
        ("Alarm_Active", False),
    ], start=1):
        obj = BinaryValueObject(
            objectIdentifier=("binaryValue", i),
            objectName=name,
            presentValue="active" if val else "inactive",
            outOfService=False,
            statusFlags=[False, False, False, False],
        )
        app.add_object(obj)

    print("BACnet/IP server running on UDP 47808 (device 599)", flush=True)
    import math
    tick = 0
    while True:
        await asyncio.sleep(5)
        tick += 1
        for obj, base in analog_objects:
            obj.presentValue = base + base * 0.05 * math.sin(tick * 0.1)

asyncio.run(main())
PYEOF
ok "BACnet/IP simulator"

# ── IEC 60870-5-104 server (pure Python) ──────────────────────────────────────
cat > "$LAB_DIR/iec104/Dockerfile" <<'EOF'
FROM python:3.12-slim
WORKDIR /app
COPY server.py .
CMD ["python", "-u", "server.py"]
EOF

cat > "$LAB_DIR/iec104/server.py" <<'PYEOF'
import socket, struct, threading, time, math, logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s IEC104 %(message)s')

# U-frame constants
STARTDT_ACT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
STARTDT_CON = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])
STOPDT_ACT  = bytes([0x68, 0x04, 0x13, 0x00, 0x00, 0x00])
STOPDT_CON  = bytes([0x68, 0x04, 0x23, 0x00, 0x00, 0x00])
TESTFR_ACT  = bytes([0x68, 0x04, 0x43, 0x00, 0x00, 0x00])
TESTFR_CON  = bytes([0x68, 0x04, 0x83, 0x00, 0x00, 0x00])

# Simulated measurement points (IOA, base_value)
MEASUREMENTS = [
    (0x000001, 350.0),   # Reactor temperature °C
    (0x000002, 12.5),    # Pressure bar
    (0x000003, 8.3),     # Flow rate m³/h
    (0x000004, 14.7),    # Motor current A
    (0x000005, 68.4),    # Tank level %
]

def build_asdu_m_me_nc1(measurements, originator=0, casdu=1):
    """Type 0x0D: M_ME_NC_1 — Short floating point value, no time tag"""
    type_id   = 0x0D
    vsq       = 0x80 | len(measurements)   # SQ=1 (sequence), count=N
    cot       = 0x03                        # COT=3 (spontaneous)
    oa        = originator
    ca        = casdu

    # Use first IOA as base IOA for the sequence
    base_ioa  = measurements[0][0]
    ioa_bytes = struct.pack('<I', base_ioa)[:3]  # 3-byte IOA LE

    values_bytes = b''
    for _, val in measurements:
        values_bytes += struct.pack('<f', val)   # 4-byte IEEE 754 LE
        values_bytes += b'\x00'                  # Quality: good

    asdu = bytes([type_id, vsq, cot, oa]) + struct.pack('<H', ca) + ioa_bytes + values_bytes
    return bytes([0x68, len(asdu) + 4]) + struct.pack('<HH', 0, 0) + asdu   # S=0, R=0 I-frame

def handle(conn, addr):
    logging.info(f"connect {addr}")
    send_seq, recv_seq = 0, 0
    started = False
    try:
        conn.settimeout(60)
        while True:
            hdr = conn.recv(2)
            if not hdr or hdr[0] != 0x68:
                break
            length = hdr[1]
            body   = conn.recv(length)
            if not body or len(body) < 4:
                break

            ctrl = body[:4]

            # U-frame detection (bits 0-1 of ctrl[0] == 11)
            if ctrl[0] & 0x03 == 0x03:
                if body[:4] == STARTDT_ACT[2:]:
                    conn.sendall(STARTDT_CON)
                    started = True
                    logging.info(f"{addr} STARTDT")
                elif body[:4] == STOPDT_ACT[2:]:
                    conn.sendall(STOPDT_CON)
                    started = False
                elif body[:4] == TESTFR_ACT[2:]:
                    conn.sendall(TESTFR_CON)
            # S-frame (bits 0-1 == 01): supervisory — just ACK
            elif ctrl[0] & 0x01 == 0x01:
                pass
            # I-frame (bit 0 == 0): data transfer
            else:
                recv_seq += 1
                if started:
                    # Send current measurements as spontaneous data
                    tick = time.time()
                    current = [
                        (ioa, base + base * 0.03 * math.sin(tick / 60 + ioa))
                        for ioa, base in MEASUREMENTS
                    ]
                    conn.sendall(build_asdu_m_me_nc1(current))
                    send_seq += 1

    except Exception as e:
        logging.debug(f"session end {addr}: {e}")
    finally:
        conn.close()
        logging.info(f"disconnect {addr}")

def spontaneous_task(clients, lock):
    """Send periodic spontaneous updates to all connected clients."""
    while True:
        time.sleep(10)
        tick = time.time()
        current = [
            (ioa, base + base * 0.03 * math.sin(tick / 60 + ioa))
            for ioa, base in MEASUREMENTS
        ]
        pdu = build_asdu_m_me_nc1(current)
        with lock:
            dead = []
            for c in clients:
                try:
                    c.sendall(pdu)
                except Exception:
                    dead.append(c)
            for c in dead:
                clients.remove(c)

clients, lock = [], threading.Lock()
threading.Thread(target=spontaneous_task, args=(clients, lock), daemon=True).start()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', 2404))
srv.listen(16)
logging.info("IEC 60870-5-104 server on TCP 2404")
while True:
    conn, addr = srv.accept()
    with lock:
        clients.append(conn)
    threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
PYEOF
ok "IEC 60870-5-104 simulator"

# ── DNP3 outstation (pydnp3) ───────────────────────────────────────────────────
cat > "$LAB_DIR/dnp3/Dockerfile" <<'EOF'
FROM python:3.8-slim
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends gcc g++ cmake make libssl-dev python3-dev && \
    pip install --no-cache-dir pydnp3==0.2.0.2 && \
    apt-get purge -y -qq gcc g++ cmake make && apt-get autoremove -y -qq && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY outstation.py .
CMD ["python", "-u", "outstation.py"]
EOF

cat > "$LAB_DIR/dnp3/outstation.py" <<'PYEOF'
import pydnp3.opendnp3 as opendnp3
import pydnp3.asiopal as asiopal
import pydnp3.asiodnp3 as asiodnp3
import time, math, logging

logging.basicConfig(level=logging.WARNING)

class OutstationApp(opendnp3.IOutstationApplication):
    def __init__(self): super().__init__()
    def SupportsWriteAbsoluteTime(self): return False
    def GetApplicationIIN(self): return opendnp3.ApplicationIIN()

manager = asiodnp3.DNP3Manager(1, asiodnp3.ConsoleLogger().Create())

channel = manager.AddTCPServer(
    "outstation", opendnp3.levels.NOTHING,
    asiopal.ChannelRetry.Default(),
    "0.0.0.0", 20000,
    asiodnp3.PrintingChannelListener().Create()
)

sizes = opendnp3.DatabaseSizes()
sizes.numBinary = 8
sizes.numAnalog = 6
sizes.numCounter = 4
sizes.numBinaryOutputStatus = 4
sizes.numAnalogOutputStatus = 2

cfg = opendnp3.OutstationStackConfig(sizes)
cfg.outstation.eventBufferConfig = opendnp3.EventBufferConfig.AllTypes(16)
cfg.outstation.params.allowUnsolicited = True
cfg.link.LocalAddr = 10
cfg.link.RemoteAddr = 1

outstation = channel.AddOutstation(
    "outstation",
    asiodnp3.PrintingCommandHandler().Create(),
    OutstationApp(),
    cfg
)

def seed():
    b = asiodnp3.UpdateBuilder()
    # Binary inputs: pump and valve states
    for i, v in enumerate([True, True, False, True, True, False, True, False]):
        b.Update(opendnp3.Binary(v), i)
    # Analog inputs: process measurements
    for i, v in enumerate([350.0, 12.5, 8.3, 14.7, 68.4, 1.0]):
        b.Update(opendnp3.Analog(v), i)
    # Counters: production and fault counts
    for i, v in enumerate([10842, 3, 0, 7]):
        b.Update(opendnp3.Counter(v), i)
    outstation.Apply(b.Build())

outstation.Enable()
seed()
print("DNP3 outstation on TCP 20000 (master=1, outstation=10)", flush=True)

tick = 0
while True:
    time.sleep(5)
    tick += 1
    b = asiodnp3.UpdateBuilder()
    b.Update(opendnp3.Analog(350.0 + 15.0 * math.sin(tick * 0.1)), 0)
    b.Update(opendnp3.Analog(12.5  + 1.0  * math.cos(tick * 0.07)), 1)
    b.Update(opendnp3.Analog(8.3   + 0.5  * math.sin(tick * 0.13)), 2)
    outstation.Apply(b.Build())
PYEOF
ok "DNP3 outstation"

# ── EtherNet/IP (cpppo) ────────────────────────────────────────────────────────
cat > "$LAB_DIR/enip/Dockerfile" <<'EOF'
FROM python:3.12-slim
RUN pip install --no-cache-dir cpppo==4.3.9
WORKDIR /app
CMD ["python", "-m", "cpppo.server.enip", \
     "--print", "--no-delay", \
     "Reactor_Temp=REAL", \
     "Motor_RPM=INT", \
     "Valve_Position=REAL", \
     "Tank_Level=REAL", \
     "PumpStatus=BOOL[4]", \
     "ProductionCount=DINT", \
     "AlarmFlags=INT"]
EOF
ok "EtherNet/IP (CIP) simulator"

# ── SLMP (Mitsubishi, TCP 5007) ────────────────────────────────────────────────
cat > "$LAB_DIR/slmp/Dockerfile" <<'EOF'
FROM python:3.12-slim
WORKDIR /app
COPY sim.py .
CMD ["python", "-u", "sim.py"]
EOF

cat > "$LAB_DIR/slmp/sim.py" <<'PYEOF'
import socket, struct, threading, logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s SLMP %(message)s')

# Simulated device memory (D registers: word values)
D_REG = [0] * 256
D_REG[0]   = 3502      # Reactor temp * 10
D_REG[1]   = 1250      # Pressure * 100
D_REG[2]   = 830       # Flow rate * 100
D_REG[3]   = 1470      # Motor current * 100
D_REG[4]   = 684       # Tank level * 10
D_REG[10]  = 10842     # Production counter (lo)
D_REG[11]  = 0         # Production counter (hi)
D_REG[100] = 0x0001    # Status word: running

def crc16(data):
    # SLMP does not use CRC in 3E frames — placeholder
    return 0

def parse_3e_frame(raw):
    """Parse SLMP 3E binary frame. Returns (serial, command, subcommand, payload) or None."""
    if len(raw) < 9 or raw[0:2] != b'\x50\x00':
        return None
    # Subheader(2) + Serial(2) + Reserved(2) + DataLen(2) + Timer(2) + Cmd(2) + SubCmd(2)
    if len(raw) < 13:
        return None
    serial     = struct.unpack_from('<H', raw, 2)[0]
    data_len   = struct.unpack_from('<H', raw, 6)[0]
    timer      = struct.unpack_from('<H', raw, 8)[0]
    command    = struct.unpack_from('<H', raw, 10)[0]
    subcommand = struct.unpack_from('<H', raw, 12)[0]
    payload    = raw[14:]
    return serial, command, subcommand, payload

def build_3e_response(serial, end_code, data=b''):
    """Build SLMP 3E binary response frame."""
    # Subheader(2=0xD000) + Serial(2) + Reserved(2) + DataLen(2) + EndCode(2) + Data
    body = struct.pack('<HHHH', 0x00D0, serial, 0x0000, 2 + len(data)) + \
           struct.pack('<H', end_code) + data
    return body

def handle_cmd(command, subcommand, payload):
    """Dispatch SLMP command and return (end_code, response_data)."""
    if command == 0x0401:  # Device Read Batch in Words
        if len(payload) < 6:
            return 0x4002, b''     # bad data
        start = struct.unpack_from('<H', payload, 0)[0]
        count = struct.unpack_from('<H', payload, 2)[0]
        # Device code is payload[4] (e.g. 0x44='D' for D register)
        vals  = D_REG[start:start + count]
        if len(vals) < count:
            vals += [0] * (count - len(vals))
        return 0x0000, struct.pack(f'<{count}H', *vals)

    elif command == 0x0403:  # Device Write Batch in Words
        if len(payload) < 6:
            return 0x4002, b''
        start = struct.unpack_from('<H', payload, 0)[0]
        count = struct.unpack_from('<H', payload, 2)[0]
        for i in range(count):
            if start + i < len(D_REG):
                D_REG[start + i] = struct.unpack_from('<H', payload, 6 + i * 2)[0]
        return 0x0000, b''

    elif command == 0x0619:  # Remote RUN
        return 0x0000, b''
    elif command == 0x061A:  # Remote STOP
        return 0x0000, b''
    else:
        return 0xC059, b''  # command not supported

def handle(conn, addr):
    logging.info(f"connect {addr}")
    try:
        conn.settimeout(30)
        buf = b''
        while True:
            chunk = conn.recv(256)
            if not chunk:
                break
            buf += chunk
            parsed = parse_3e_frame(buf)
            if parsed is None:
                if len(buf) > 512:
                    buf = b''
                continue
            buf = b''
            serial, cmd, subcmd, payload = parsed
            end_code, data = handle_cmd(cmd, subcmd, payload)
            conn.sendall(build_3e_response(serial, end_code, data))
    except Exception as e:
        logging.debug(f"session {addr}: {e}")
    finally:
        conn.close()
        logging.info(f"disconnect {addr}")

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', 5007))
srv.listen(16)
logging.info("SLMP 3E binary server on TCP 5007")
while True:
    conn, addr = srv.accept()
    threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
PYEOF
ok "SLMP (Mitsubishi) simulator"

# ── FINS (Omron, UDP 9600) ─────────────────────────────────────────────────────
cat > "$LAB_DIR/fins/Dockerfile" <<'EOF'
FROM python:3.12-slim
WORKDIR /app
COPY sim.py .
CMD ["python", "-u", "sim.py"]
EOF

cat > "$LAB_DIR/fins/sim.py" <<'PYEOF'
import socket, struct, logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s FINS %(message)s')

# Simulated memory areas
DM  = [0] * 512   # DM area (area code 0x82, word)
CIO = [0] * 512   # CIO area (area code 0x30, word)
HR  = [0] * 128   # HR area (area code 0xB2, word)

# Populate DM with realistic values
DM[0]  = 3502    # Reactor temp * 10
DM[1]  = 1250    # Pressure * 100
DM[2]  = 8300    # Flow * 1000
DM[10] = 10842   # Counter lo
DM[11] = 0       # Counter hi
DM[20] = 0x0101  # Status: running + OK

# CIO: I/O bits as words
CIO[0] = 0x00FF  # 8 inputs ON
CIO[1] = 0x000F  # 4 outputs ON

AREA_MAP = {
    0x82: DM,   # DM area
    0x30: CIO,  # CIO area
    0xB2: HR,   # HR area
}

CONTROLLER_INFO = (
    b'CS1G-CPU42H     '   # 16 bytes: model
    b'\x04'               # CPU unit number
    b'\x00'               # internal bus unit count
    b'\x00\x10'           # program area size (pages)
    b'\x00\x20\x00'       # IOM size
    b'\x00\x04'           # no. of DM words
    b'\x00'               # timer/counter size
    b'\x00\x01'           # expansion DM size
    b'\x00' * 6           # padding
)

def fins_resp_header(req):
    h = bytearray(10)
    h[0] = 0xC0 | (req[0] & 0x0F)  # ICF response
    h[1] = 0x00   # RSV
    h[2] = req[2] # GCT
    h[3] = req[6]  # DNA ← SNA from request
    h[4] = req[7]  # DA1 ← SA1
    h[5] = req[8]  # DA2 ← SA2
    h[6] = req[3]  # SNA ← DNA
    h[7] = req[4]  # SA1 ← DA1
    h[8] = req[5]  # SA2 ← DA2
    h[9] = req[9]  # SID
    return bytes(h)

def handle_command(mrc, src, payload):
    """Returns (end_code_2bytes, response_data)."""

    if mrc == 0x01 and src == 0x01:  # Memory Area Read
        if len(payload) < 6:
            return b'\x10\x01', b''
        area = payload[0]
        start = struct.unpack_from('>H', payload, 1)[0]
        elem  = payload[3]                        # bit position (0 for word access)
        count = struct.unpack_from('>H', payload, 4)[0]
        mem   = AREA_MAP.get(area, DM)
        words = mem[start:start + count]
        if len(words) < count:
            words += [0] * (count - len(words))
        return b'\x00\x00', struct.pack(f'>{count}H', *words)

    elif mrc == 0x01 and src == 0x02:  # Memory Area Write
        if len(payload) < 8:
            return b'\x10\x01', b''
        area  = payload[0]
        start = struct.unpack_from('>H', payload, 1)[0]
        count = struct.unpack_from('>H', payload, 4)[0]
        mem   = AREA_MAP.get(area, DM)
        for i in range(count):
            offset = 6 + i * 2
            if start + i < len(mem) and offset + 2 <= len(payload):
                mem[start + i] = struct.unpack_from('>H', payload, offset)[0]
        return b'\x00\x00', b''

    elif mrc == 0x05 and src == 0x01:  # Controller Data Read
        return b'\x00\x00', CONTROLLER_INFO

    elif mrc == 0x06 and src == 0x01:  # Controller Status Read
        data = struct.pack('>HHH', 0x0001, 0x0000, 0x0000)  # running, no error
        return b'\x00\x00', data

    else:
        return b'\x04\x01', b''   # command not supported

srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', 9600))
logging.info("FINS server on UDP 9600")
while True:
    try:
        raw, addr = srv.recvfrom(1024)
        if len(raw) < 12:
            continue
        mrc = raw[10]
        src = raw[11]
        logging.info(f"{addr} MRC={mrc:#04x} SRC={src:#04x}")
        end_code, data = handle_command(mrc, src, raw[12:])
        resp = fins_resp_header(raw) + bytes([mrc, src]) + end_code + data
        srv.sendto(resp, addr)
    except Exception as e:
        logging.warning(f"error: {e}")
PYEOF
ok "FINS (Omron) simulator"

# ── Pull public images ──────────────────────────────────────────────────────────
section "Pulling Public Images"
pull_if_missing "honeynet/conpot:latest"   || true
pull_if_missing "eclipse-mosquitto:latest" || true

# ── Build custom images ─────────────────────────────────────────────────────────
section "Building Custom Images"
build_if_missing "ics-lab/opcua:latest"   "$LAB_DIR/opcua"   || true
build_if_missing "ics-lab/bacnet:latest"  "$LAB_DIR/bacnet"  || true
build_if_missing "ics-lab/iec104:latest"  "$LAB_DIR/iec104"  || true
build_if_missing "ics-lab/dnp3:latest"    "$LAB_DIR/dnp3"    || true
build_if_missing "ics-lab/enip:latest"    "$LAB_DIR/enip"    || true
build_if_missing "ics-lab/slmp:latest"    "$LAB_DIR/slmp"    || true
build_if_missing "ics-lab/fins:latest"    "$LAB_DIR/fins"    || true

# ── Start containers ────────────────────────────────────────────────────────────
section "Starting Containers"

# Conpot — Modbus TCP (502), S7Comm (102), SNMP UDP (161), HTTP (8080→8180)
start_container "ics-conpot" \
    -p 502:502 \
    -p 102:102 \
    -p 161:161/udp \
    -p 8180:8080 \
    honeynet/conpot:latest \
    || true

# MQTT — Mosquitto TCP 1883
start_container "ics-mqtt" \
    -p 1883:1883 \
    -v "$LAB_DIR/mosquitto/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro" \
    eclipse-mosquitto:latest \
    || true

# OPC-UA — TCP 4840
if docker image inspect "ics-lab/opcua:latest" &>/dev/null 2>&1; then
    start_container "ics-opcua" -p 4840:4840 ics-lab/opcua:latest || true
fi

# BACnet — UDP 47808
if docker image inspect "ics-lab/bacnet:latest" &>/dev/null 2>&1; then
    start_container "ics-bacnet" -p 47808:47808/udp ics-lab/bacnet:latest || true
fi

# IEC 104 — TCP 2404
if docker image inspect "ics-lab/iec104:latest" &>/dev/null 2>&1; then
    start_container "ics-iec104" -p 2404:2404 ics-lab/iec104:latest || true
fi

# DNP3 — TCP 20000
if docker image inspect "ics-lab/dnp3:latest" &>/dev/null 2>&1; then
    start_container "ics-dnp3" -p 20000:20000 ics-lab/dnp3:latest || true
fi

# EtherNet/IP — TCP 44818
if docker image inspect "ics-lab/enip:latest" &>/dev/null 2>&1; then
    start_container "ics-enip" -p 44818:44818 ics-lab/enip:latest || true
fi

# SLMP (Mitsubishi) — TCP 5007
if docker image inspect "ics-lab/slmp:latest" &>/dev/null 2>&1; then
    start_container "ics-slmp" -p 5007:5007 ics-lab/slmp:latest || true
fi

# FINS (Omron) — UDP 9600
if docker image inspect "ics-lab/fins:latest" &>/dev/null 2>&1; then
    start_container "ics-fins" -p 9600:9600/udp ics-lab/fins:latest || true
fi

# ── Health check ────────────────────────────────────────────────────────────────
section "Health Check"
sleep 4

check_tcp() {
    local label="$1" port="$2"
    if timeout 2 bash -c ">/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
        ok "$label on :$port"
    else
        warn "$label on :$port — may still be initialising"
    fi
}

check_tcp "Modbus TCP (Conpot)"     502
check_tcp "S7Comm (Conpot)"         102
check_tcp "MQTT (Mosquitto)"        1883
check_tcp "OPC-UA"                  4840
check_tcp "IEC 104"                 2404
check_tcp "DNP3"                    20000
check_tcp "EtherNet/IP"             44818
check_tcp "SLMP (Mitsubishi)"       5007

ok "SNMP on UDP 161 (Conpot — UDP, skipping probe)"
ok "BACnet on UDP 47808 (skipping probe)"
ok "FINS on UDP 9600 (skipping probe)"

# ── Summary ─────────────────────────────────────────────────────────────────────
HOST=$(hostname -I | awk '{print $1}')
echo -e ""
echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║         ICS Lab Ready  ·  ${HOST}           ║${NC}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
printf "\n  %-26s %-20s %s\n" "Protocol" "Container" "Port"
printf "  %s\n" "──────────────────────────────────────────────────────"
printf "  %-26s %-20s %s\n" "Modbus TCP"          "ics-conpot"   "TCP  502"
printf "  %-26s %-20s %s\n" "Siemens S7Comm"      "ics-conpot"   "TCP  102"
printf "  %-26s %-20s %s\n" "SNMP"                "ics-conpot"   "UDP  161"
printf "  %-26s %-20s %s\n" "Siemens HTTP"        "ics-conpot"   "TCP  8180"
printf "  %-26s %-20s %s\n" "MQTT"                "ics-mqtt"     "TCP  1883"
printf "  %-26s %-20s %s\n" "OPC-UA"              "ics-opcua"    "TCP  4840"
printf "  %-26s %-20s %s\n" "BACnet/IP"           "ics-bacnet"   "UDP  47808"
printf "  %-26s %-20s %s\n" "IEC 60870-5-104"     "ics-iec104"   "TCP  2404"
printf "  %-26s %-20s %s\n" "DNP3"                "ics-dnp3"     "TCP  20000"
printf "  %-26s %-20s %s\n" "EtherNet/IP (CIP)"   "ics-enip"     "TCP  44818"
printf "  %-26s %-20s %s\n" "SLMP (Mitsubishi)"   "ics-slmp"     "TCP  5007"
printf "  %-26s %-20s %s\n" "FINS (Omron)"        "ics-fins"     "UDP  9600"
echo ""
echo -e "  ${BOLD}Management:${NC}"
echo -e "  Status:     sudo bash ics-lab-setup.sh --status"
echo -e "  Stop all:   sudo bash ics-lab-setup.sh --stop"
echo -e "  Remove all: sudo bash ics-lab-setup.sh --remove"
echo -e "  Logs:       docker logs <container-name>"
echo -e "  Rebuild:    docker rmi ics-lab/<name>:latest  # then re-run this script"
echo ""
echo -e "  ${BOLD}Point scadaver at:${NC} ${HOST}"
echo ""
