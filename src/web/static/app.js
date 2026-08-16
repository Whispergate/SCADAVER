'use strict';

// ─── Exploit definitions per vendor ──────────────────────────────────────────
const EXPLOIT_CATALOG = {
    ewon: [
        {
            id: 'ewon/creds',
            name: 'Credential Dump',
            desc: 'Extract all user accounts and decoded passwords from an eWON device.',
            params: [],
        },
    ],
    schneider: [
        {
            id: 'schneider/flash',
            name: 'Flash LED',
            desc: 'Send the identification LED flash command to a Schneider PLC.',
            params: [],
        },
        {
            id: 'schneider/session_stop',
            name: 'Session Hijack: Stop',
            desc: 'CVE-2017-6026: steal cookie from FwLog.txt and send Stop command.',
            params: [],
            destructive: true,
        },
        {
            id: 'schneider/session_run',
            name: 'Session Hijack: Start',
            desc: 'CVE-2017-6026: steal cookie from FwLog.txt and send Start command.',
            params: [],
        },
    ],
    modicon: [
        {
            id: 'schneider/flash',
            name: 'Flash LED',
            desc: 'Send the identification LED flash command.',
            params: [],
        },
        {
            id: 'modicon/write_coil',
            name: 'Write Coil (FC5)',
            desc: 'Write a single coil ON or OFF via Modbus FC5.',
            params: [
                { name: 'username', label: 'Coil Address (0-based)' },
                { name: 'password', label: 'Value  (ON / OFF)' },
            ],
            destructive: true,
        },
        {
            id: 'modicon/write_register',
            name: 'Write Register (FC6)',
            desc: 'Write a 16-bit holding register via Modbus FC6.',
            params: [
                { name: 'username', label: 'Register Address (0-based)' },
                { name: 'password', label: 'Value  (0 – 65535)' },
            ],
            destructive: true,
        },
    ],
    phoenix: [
        {
            id: 'phoenix/passwords',
            name: 'Password Dump',
            desc: 'CVE-2016-8366: retrieve WebVisit HMI user passwords.',
            params: [],
        },
    ],
    beckhoff: [
        {
            id: 'beckhoff/reboot',
            name: 'Reboot Device',
            desc: 'CVE-2015-4051: trigger a remote reboot via the UPnP SOAP service.',
            params: [],
            destructive: true,
        },
        {
            id: 'beckhoff/add_user',
            name: 'Add Admin User',
            desc: 'CVE-2015-4051: inject a new admin account via the UPnP SOAP service.',
            params: [
                { name: 'username', label: 'New Username' },
                { name: 'password', label: 'New Password' },
            ],
            destructive: true,
        },
    ],
    siemens: [],
    omron: [
        {
            id: 'omron/info',
            name: 'Get Device Info (FINS)',
            desc: 'Read controller model and version via FINS command 05 01 (Controller Data Read).',
            params: [],
        },
        {
            id: 'omron/cpu_status',
            name: 'CPU Status',
            desc: 'Read current CPU operating mode (Stop / Run / Monitor / Program) via FINS command 06 01.',
            params: [],
        },
        {
            id: 'omron/cpu_run',
            name: 'CPU Run (Monitor mode)',
            desc: 'Set CPU to Monitor mode via FINS command 04 01. Equivalent to pressing RUN on the keyswitch.',
            params: [],
            destructive: true,
        },
        {
            id: 'omron/cpu_stop',
            name: 'CPU Stop',
            desc: 'Set CPU to Stop mode via FINS command 04 01. Halts program execution.',
            params: [],
            destructive: true,
        },
        {
            id: 'omron/read_dm',
            name: 'Read DM Words',
            desc: 'Read 16-bit words from the DM (Data Memory) area via FINS.',
            params: [
                { name: 'username', label: 'Start Address (default 0)' },
                { name: 'password', label: 'Count (default 10, max 100)' },
            ],
        },
        {
            id: 'omron/write_dm',
            name: 'Write DM Words',
            desc: 'Write 16-bit words to DM area via FINS. Username = start address, Password = space-separated values.',
            params: [
                { name: 'username', label: 'Start Address' },
                { name: 'password', label: 'Values (space-separated, e.g. 100 200 300)' },
            ],
            destructive: true,
        },
    ],
    mitsubishi: [
        {
            id: 'mitsubishi/info',
            name: 'Get Device Info (SLMP)',
            desc: 'Probe via GX Works3 UDP discovery and SLMP to retrieve PLC model and protocol info.',
            params: [],
        },
        {
            id: 'mitsubishi/read_d',
            name: 'Read D Registers',
            desc: 'Read MELSEC D word registers via SLMP 3E batch read (TCP port 5007).',
            params: [
                { name: 'username', label: 'Start Address (default 0)' },
                { name: 'password', label: 'Count (default 20, max 100)' },
            ],
        },
        {
            id: 'mitsubishi/read_m',
            name: 'Read M Bits',
            desc: 'Read MELSEC M bit devices via SLMP 3E batch read (TCP port 5007).',
            params: [
                { name: 'username', label: 'Start Address (default 0)' },
                { name: 'password', label: 'Count (default 20, max 100)' },
            ],
        },
    ],
    iec104: [
        {
            id: 'iec104/gi',
            name: 'General Interrogation',
            desc: 'Send C_IC_NA_1 (TypeID 100) and collect all returned data objects from the outstation.',
            params: [],
        },
        {
            id: 'iec104/sc_on',
            name: 'Single Command ON',
            desc: 'Send C_SC_NA_1 ON to the specified IOA (port 2404). Username = IOA (default 1).',
            params: [{ name: 'username', label: 'IOA (default 1)' }],
            destructive: true,
        },
        {
            id: 'iec104/sc_off',
            name: 'Single Command OFF',
            desc: 'Send C_SC_NA_1 OFF to the specified IOA (port 2404). Username = IOA (default 1).',
            params: [{ name: 'username', label: 'IOA (default 1)' }],
            destructive: true,
        },
    ],
    rockwell: [
        {
            id: 'rockwell/identity',
            name: 'Get Device Identity',
            desc: 'Read vendor, product name, revision, and serial number via EtherNet/IP List Identity (port 44818).',
            params: [],
        },
        {
            id: 'rockwell/list_tags',
            name: 'List Tags',
            desc: 'Enumerate tag names and types from the Logix symbol table (up to 50 tags).',
            params: [],
        },
    ],
    snmp: [
        {
            id: 'snmp/sys_info',
            name: 'System Info',
            desc: 'Walk MIB-II system subtree (.1.3.6.1.2.1.1) with community "public".',
            params: [],
        },
        {
            id: 'snmp/interfaces',
            name: 'Interface Table',
            desc: 'Walk MIB-II interfaces subtree (.1.3.6.1.2.1.2) with community "public".',
            params: [],
        },
        {
            id: 'snmp/walk',
            name: 'Walk OID Subtree',
            desc: 'Walk a custom OID subtree. Username = community string, Password = OID prefix.',
            params: [
                { name: 'username', label: 'Community (default: public)' },
                { name: 'password', label: 'OID prefix (default: .1.3.6.1.2.1.1)' },
            ],
        },
    ],
    // Common exploits shown for every vendor (SCASS paper attack coverage)
    common: [
        {
            id: 'common/shellshock',
            name: 'Shellshock Scanner',
            desc: 'CVE-2014-6271: test CGI endpoints on port 80 for Shellshock (bash RCE). Used in SCASS §6.3.2 against PLC/HMI web servers.',
            params: [],
        },
        {
            id: 'common/http_creds',
            name: 'HTTP Default Creds',
            desc: 'Try common ICS factory default credentials against HTTP Basic Auth (port 80). Based on SCADAPASS database.',
            params: [],
        },
    ],
};

// ─── Alpine.js application ────────────────────────────────────────────────────
function scadaApp() {
    return {
        // ── State ──────────────────────────────────────────────────────────
        apiKey: new URLSearchParams(window.location.search).get('key') || '',
        activeTab: 'scanner',
        devices: [],
        selectedDevice: null,

        // Scanner
        interfaces: [],
        selectedIface: '',
        scanVendor: 'all',
        scanTimeout: 5,
        scanning: false,
        scanResults: [],
        probeIp: '',
        probing: false,
        portScanResults: [],
        portScanning: false,

        // Tags
        tags: {},
        tagsLoading: false,
        tagsError: '',
        editingTag: null,
        editValue: '',
        writingTag: false,

        // Monitor
        monitorRunning: false,
        monitorTags: {},
        monitorError: '',
        monitorEmptyStreak: 0,
        monitorUserDisconnected: false,
        ws: null,

        // Exploits
        exploitParams: {},
        exploitRunning: {},
        exploitResults: {},

        // Toast
        toast: null,
        toastTimer: null,

        // Confirm modal
        confirmVisible: false,
        confirmMessage: '',
        confirmCallback: null,

        // ── Lifecycle ──────────────────────────────────────────────────────
        async init() {
            await Promise.all([this.loadDevices(), this.loadInterfaces()]);
        },

        // ── Devices ────────────────────────────────────────────────────────
        async loadDevices() {
            try {
                const r = await fetch('/api/devices');
                const data = await r.json();
                this.devices = data.devices || [];
            } catch {
                this.devices = [];
            }
        },

        async addDevice(dev) {
            await fetch('/api/devices', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: dev.ip, vendor: dev.vendor, fields: dev }),
            });
            await this.loadDevices();
        },

        async removeDevice(ip) {
            await fetch(`/api/devices/${ip}`, { method: 'DELETE' });
            if (this.selectedDevice?.ip === ip) {
                this.selectedDevice = null;
                this.tags = {};
            }
            await this.loadDevices();
        },

        selectDevice(dev) {
            this.selectedDevice = dev;
            this.activeTab = 'identity';
            this.tags = {};
            this.tagsError = '';
            this.editingTag = null;
            this.monitorTags = {};
        },

        identityList() {
            if (!this.selectedDevice?.fields) return [];
            return Object.entries(this.selectedDevice.fields)
                .filter(([k, v]) => {
                    if (k === '_tags') return false;
                    if (k.startsWith('cap_')) return false;
                    return v !== null && v !== undefined && String(v).length > 0;
                })
                .map(([k, v]) => ({ key: k, value: String(v) }));
        },

        vendorBadgeClass(vendor) {
            return `badge-${vendor || 'unknown'}`;
        },

        // ── Interfaces ─────────────────────────────────────────────────────
        async loadInterfaces() {
            try {
                const r = await fetch('/api/interfaces');
                const data = await r.json();
                this.interfaces = data.interfaces || [];
                if (this.interfaces.length > 0) {
                    this.selectedIface = this.interfaces[0].ip;
                }
            } catch {
                this.interfaces = [];
            }
        },

        // ── Scanner tab ────────────────────────────────────────────────────
        async scanNetwork() {
            this.scanning = true;
            this.scanResults = [];
            try {
                const r = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-Key': this.apiKey },
                    body: JSON.stringify({
                        vendor: this.scanVendor,
                        timeout: this.scanTimeout,
                        iface_ip: this.selectedIface,
                    }),
                });
                const data = await r.json();
                if (data.error) {
                    this.showToast(data.error, 'error');
                } else {
                    this.scanResults = data.devices || [];
                    this.showToast(`Found ${this.scanResults.length} device(s).`, 'success');
                }
            } catch (e) {
                this.showToast(`Scan error: ${e}`, 'error');
            } finally {
                this.scanning = false;
            }
        },

        async probeIpTarget() {
            if (!this.probeIp.trim()) return;
            this.probing = true;
            try {
                const r = await fetch('/api/scan/ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-Key': this.apiKey },
                    body: JSON.stringify({ ip: this.probeIp.trim(), timeout: this.scanTimeout }),
                });
                const data = await r.json();
                if (data.error) {
                    this.showToast(data.error, 'error');
                } else {
                    await this.addDevice(data);
                    this.showToast(`Detected: ${data.vendor} @ ${data.ip}`, 'success');
                    this.probeIp = '';
                }
            } catch (e) {
                this.showToast(`Probe error: ${e}`, 'error');
            } finally {
                this.probing = false;
            }
        },

        async addScanResult(dev) {
            await this.addDevice(dev);
            this.showToast(`Added ${dev.ip} to device list.`, 'success');
        },

        async scanPorts() {
            if (!this.selectedDevice) return;
            this.portScanning = true;
            this.portScanResults = [];
            try {
                const r = await fetch('/api/run/portscan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip: this.selectedDevice.ip,
                        timeout: this.scanTimeout,
                        extra_ports: [],
                    }),
                });
                const data = await r.json();
                this.portScanResults = data.ports || [];
                this.showToast(`Found ${this.portScanResults.length} open port(s).`, 'success');
            } catch (e) {
                this.showToast(`Port scan error: ${e}`, 'error');
            } finally {
                this.portScanning = false;
            }
        },

        // ── Tags tab ───────────────────────────────────────────────────────
        async loadTags() {
            if (!this.selectedDevice) return;
            this.tagsLoading = true;
            this.tagsError = '';
            try {
                const r = await fetch('/api/device/tags', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-Key': this.apiKey },
                    body: JSON.stringify({
                        ip: this.selectedDevice.ip,
                        vendor: this.selectedDevice.vendor,
                        cache: false,
                    }),
                });
                const data = await r.json();
                if (data.error) {
                    this.tagsError = data.error;
                } else {
                    this.tags = data.tags || {};
                }
            } catch (e) {
                this.tagsError = String(e);
            } finally {
                this.tagsLoading = false;
            }
        },

        async loadTagsCached() {
            if (!this.selectedDevice) return;
            this.tagsLoading = true;
            this.tagsError = '';
            try {
                const r = await fetch('/api/device/tags', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-Key': this.apiKey },
                    body: JSON.stringify({
                        ip: this.selectedDevice.ip,
                        vendor: this.selectedDevice.vendor,
                        cache: true,
                    }),
                });
                const data = await r.json();
                if (data.error) {
                    this.tagsError = data.error;
                } else {
                    this.tags = data.tags || {};
                }
            } catch (e) {
                this.tagsError = String(e);
            } finally {
                this.tagsLoading = false;
            }
        },

        startEdit(tag, value) {
            this.editingTag = tag;
            this.editValue = String(value);
        },

        cancelEdit() {
            this.editingTag = null;
            this.editValue = '';
        },

        // `field` is a UDT member descriptor, or null for a scalar tag. For a member the
        // CIP path is "<tag>.<member path>" and the type code comes from the member, so
        // the backend never has to guess how to encode the text.
        async commitEdit(tagKey, field) {
            if (!this.selectedDevice) return;
            const entry = this.tags[tagKey];
            const target = field ? `${tagKey}.${field.path}` : tagKey;
            const typeCode = field
                ? field.type
                : (entry && typeof entry === 'object' ? entry._write_type : null);
            const newValue = this.editValue;

            this.writingTag = true;
            try {
                const r = await fetch('/api/device/write', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-Key': this.apiKey },
                    body: JSON.stringify({
                        ip: this.selectedDevice.ip,
                        vendor: this.selectedDevice.vendor,
                        tag: target,
                        value: newValue,
                        type_code: typeCode ?? null,
                    }),
                });
                const data = await r.json();
                if (data.success) {
                    this.applyWrittenValue(tagKey, field, newValue);
                    this.showToast(`Write OK: ${target} = ${newValue}`, 'success');
                } else {
                    this.showToast(`Write failed: ${data.error}`, 'error');
                }
            } catch (e) {
                this.showToast(`Write error: ${e}`, 'error');
            } finally {
                this.writingTag = false;
                this.editingTag = null;
                this.editValue = '';
            }
        },

        // Reflect a successful write locally so the row updates without a full re-pull.
        applyWrittenValue(tagKey, field, newValue) {
            const entry = this.tags[tagKey];
            if (field && entry && Array.isArray(entry._fields)) {
                const member = entry._fields.find(f => f.path === field.path);
                if (member) member.value = newValue;
                return;
            }
            if (entry && typeof entry === 'object') {
                entry._display = newValue;
            } else {
                this.tags[tagKey] = newValue;
            }
        },

        // Normalises both response shapes: a bare string (vendors that return plain
        // values) and the richer object the Rockwell path returns. `fields` is non-null
        // only for UDTs, which is what the table branches on.
        tagList() {
            return Object.entries(this.tags).map(([k, v]) => {
                if (v === null || typeof v !== 'object') {
                    return {
                        key: k, value: String(v), fields: null,
                        type: '', writable: true, writeType: null,
                    };
                }
                return {
                    key: k,
                    value: v._display ?? JSON.stringify(v),
                    fields: Array.isArray(v._fields) ? v._fields : null,
                    type: v._type ?? '',
                    writable: v._writable !== false,
                    writeType: v._write_type ?? null,
                };
            });
        },

        // Identity for the "which cell is being edited" state. A UDT member is keyed by
        // tag + member path so two members of the same tag never collide.
        fieldKey(tagKey, field) {
            return field ? `${tagKey}.${field.path}` : tagKey;
        },

        // ── Monitor tab ────────────────────────────────────────────────────
        connectMonitor() {
            if (!this.selectedDevice) return;
            this.monitorUserDisconnected = false;
            this.disconnectMonitor();
            const vendor = this.selectedDevice.vendor;
            const ip = this.selectedDevice.ip;
            const proto = `${location.protocol === 'https:' ? 'wss' : 'ws'}:`;
            this.ws = new WebSocket(`${proto}//${location.host}/ws/monitor/${ip}?vendor=${vendor}`);
            this.monitorRunning = true;
            this.monitorError = '';
            this.monitorEmptyStreak = 0;

            this.ws.onmessage = (ev) => {
                try {
                    const data = JSON.parse(ev.data);
                    if (data.error) {
                        this.monitorError = data.error;
                    } else {
                        const prev = this.monitorTags;
                        const next = data.tags || {};
                        if (Object.keys(next).length === 0) {
                            this.monitorEmptyStreak++;
                            if (this.monitorEmptyStreak >= 3) {
                                this.monitorError = 'No data returned. Device may be offline or vendor not supported.';
                            }
                        } else {
                            this.monitorEmptyStreak = 0;
                            this.monitorError = '';
                            // Flash cells that changed
                            this.$nextTick(() => {
                                Object.keys(next).forEach((k) => {
                                    if (prev[k] !== undefined && prev[k] !== next[k]) {
                                        const el = document.getElementById(`mon-${k.replace(/[^a-z0-9]/gi, '_')}`);
                                        if (el) {
                                            el.classList.remove('value-changed');
                                            void el.offsetWidth; // reflow
                                            el.classList.add('value-changed');
                                        }
                                    }
                                });
                            });
                            this.monitorTags = next;
                        }
                    }
                } catch (e) { this.monitorError = `Monitor protocol error: ${e}`; }
            };

            this.ws.onerror = () => {
                this.monitorError = 'WebSocket connection error.';
            };

            this.ws.onclose = () => {
                this.monitorRunning = false;
                if (!this.monitorUserDisconnected) {
                    this.monitorError = 'Monitor connection lost. Device may be unreachable.';
                }
            };
        },

        disconnectMonitor() {
            if (this.ws) {
                this.monitorUserDisconnected = true;
                this.ws.close();
                this.ws = null;
            }
            this.monitorRunning = false;
        },

        monitorList() {
            return Object.entries(this.monitorTags).map(([k, v]) => ({
                key: k,
                value: (v !== null && typeof v === 'object') ? JSON.stringify(v) : String(v),
            }));
        },

        monitorCellId(key) {
            return `mon-${key.replace(/[^a-z0-9]/gi, '_')}`;
        },

        // ── Exploits tab ───────────────────────────────────────────────────
        availableExploits() {
            const vendor = this.selectedDevice?.vendor || '';
            const vendorExploits = EXPLOIT_CATALOG[vendor] || [];
            const commonExploits = EXPLOIT_CATALOG['common'] || [];
            return [...vendorExploits, ...commonExploits];
        },

        initExploitParams(id) {
            if (!this.exploitParams[id]) {
                this.exploitParams[id] = { username: '', password: '' };
            }
        },

        async runExploit(expl) {
            if (!this.selectedDevice) return;
            if (expl.destructive) {
                const ok = await this.confirm(
                    `This will modify or disrupt the target device.\nProceed with "${expl.name}" on ${this.selectedDevice.ip}?`
                );
                if (!ok) return;
            }
            const params = this.exploitParams[expl.id] || {};
            this.exploitRunning[expl.id] = true;
            this.exploitResults[expl.id] = '';
            try {
                const r = await fetch(`/api/exploit/${expl.id}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-Key': this.apiKey },
                    body: JSON.stringify({
                        ip: this.selectedDevice.ip,
                        username: params.username || '',
                        password: params.password || '',
                    }),
                });
                const data = await r.json();
                if (data.success) {
                    this.exploitResults[expl.id] = data.output || '(no output)';
                    this.showToast(`${expl.name}: success`, 'success');
                } else {
                    this.exploitResults[expl.id] = `ERROR: ${data.error}`;
                    this.showToast(`${expl.name}: failed`, 'error');
                }
            } catch (e) {
                this.exploitResults[expl.id] = `Network error: ${e}`;
                this.showToast(`${expl.name}: error`, 'error');
            } finally {
                this.exploitRunning[expl.id] = false;
            }
        },

        // ── Confirm modal ──────────────────────────────────────────────────
        confirm(message) {
            return new Promise((resolve) => {
                this.confirmMessage = message;
                this.confirmVisible = true;
                this.confirmCallback = resolve;
            });
        },

        confirmYes() {
            this.confirmVisible = false;
            if (this.confirmCallback) this.confirmCallback(true);
        },

        confirmNo() {
            this.confirmVisible = false;
            if (this.confirmCallback) this.confirmCallback(false);
        },

        // ── Toast ──────────────────────────────────────────────────────────
        showToast(msg, type = 'info') {
            if (this.toastTimer) clearTimeout(this.toastTimer);
            this.toast = { msg, type };
            this.toastTimer = setTimeout(() => { this.toast = null; }, 4000);
        },
    };
}
