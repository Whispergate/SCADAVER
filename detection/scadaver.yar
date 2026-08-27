/*
 * SCADAver YARA Rules
 * Detect SCADAver binary artifacts and captured network traffic (PCAP).
 *
 * Usage:
 *   yara scadaver.yar /path/to/scan           -- file/memory scan
 *   yara scadaver.yar capture.pcap            -- PCAP artifact scan
 */

// ── Binary detection ──────────────────────────────────────────────────────────

rule SCADAver_Binary {
    meta:
        description = "Matches the SCADAver ICS red team tool binary"
        author      = "SCADAver project"
        severity    = "high"
        reference   = "https://github.com/Whispergate/SCADAVER"

    strings:
        $tool_name   = "SCADAVER" ascii wide
        $cip_class   = "Symbol Object enumeration" ascii
        $vendor_rock = "exploit_rockwell_tags" ascii
        $vendor_mod  = "exploit_modbus" ascii
        $db_path     = "scadaver/devices.db" ascii
        $eip_wm      = { 53 43 41 44 41 56 45 52 }  // "SCADAVER" EIP sender context

    condition:
        uint16(0) == 0x5A4D or         // PE
        uint32(0) == 0x464C457F        // ELF
        and 3 of them
}

rule SCADAver_EIP_Watermark_In_PCAP {
    meta:
        description = "EIP packet with SCADAver sender context watermark — indicates active scanning"
        severity    = "critical"
        note        = "Match in a PCAP means SCADAver was used against a host in this capture"

    strings:
        // EIP Register Session (0x6500) with "SCADAVER" at offset 12
        $reg_session = { 65 00 04 00 00 00 00 00 00 00 00 00
                         53 43 41 44 41 56 45 52 }

        // EIP ListIdentity (0x6300) with "SCADAVER" at offset 12
        $list_id     = { 63 00 00 00 00 00 00 00 00 00 00 00
                         53 43 41 44 41 56 45 52 }

        // EIP SendRRData (0x6F00) with "SCADAVER" at offset 12
        $send_rr     = { 6F 00 ?? ?? ?? ?? ?? ?? 00 00 00 00
                         53 43 41 44 41 56 45 52 }

    condition:
        any of them
}

// ── Network traffic artifacts (behavioral) ────────────────────────────────────

rule SCADAver_CIP_SymbolEnum {
    meta:
        description = "CIP Symbol Class (0x6B) Get Attributes — SCADAver tag enumeration pattern"
        severity    = "high"

    strings:
        // CIP Get Attribute List on Symbol Object class (0x6B) with all-instance request
        $sym_enum = { 6F 00 ?? ?? ?? ?? ?? ?? 00 00 00 00
                      53 43 41 44 41 56 45 52
                      00 00 00 00               // options
                      00 00 00 00               // interface handle
                      00 00                     // timeout
                      02 00                     // item count
                      00 00 00 00               // null address
                      B2 00                     // unconnected data
                      ?? ??                     // data length
                      55                        // Get Attribute List service
                      03 20 6B               }  // path: class 0x6B

    condition:
        $sym_enum
}

rule SCADAver_Modbus_FC43 {
    meta:
        description = "Modbus FC43 Device Identification — SCADAver device fingerprinting"
        severity    = "medium"

    strings:
        // MBAP header + FC43 (0x2B) sub-code 0x0E (Read Device ID)
        $fc43 = { ?? ?? ?? ?? 00 01 ?? 2B 0E }

    condition:
        $fc43
}

rule SCADAver_Config_DB {
    meta:
        description = "SCADAver devices.db SQLite database — tool artefact on analyst machine"
        severity    = "informational"

    strings:
        $sqlite_hdr  = { 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00 }  // "SQLite format 3"
        $table_tags  = "device_tags" ascii
        $table_mbrs  = "device_tag_members" ascii
        $table_data  = "device_data" ascii

    condition:
        $sqlite_hdr and 2 of ($table_tags, $table_mbrs, $table_data)
}
