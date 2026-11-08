//! Address-range maps for bulk reads: which Modbus tables and SLMP devices to walk,
//! and how to split a range into protocol-sized chunks.
//!
//! Pure data and parsing, no protocol I/O and no printing, so the CLI, the TUI and the
//! web surface all agree on what `hr:0:500` means. Parsing errors carry the usage line
//! instead of a bare "invalid input".

// ─── Constants ────────────────────────────────────────────────────────────────

pub const MODBUS_ADDRESS_SPACE: u32 = 65_536;
pub const MODBUS_WORD_CHUNK: u16 = 125;
pub const MODBUS_BIT_CHUNK: u16 = 2000;
pub const MODBUS_MAP_VALUE_OUTPUT_CAP: usize = 64;
pub const MODBUS_MAP_ERROR_OUTPUT_CAP: usize = 20;
pub const SLMP_ADDRESS_SPACE: u32 = 16_777_216;
pub const SLMP_WORD_CHUNK: u16 = 960;
pub const SLMP_BIT_CHUNK: u16 = 3584;

// ─── ModbusTable ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModbusTable {
    Holding,
    Input,
    Coil,
    Discrete,
}

impl ModbusTable {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "hr" | "holding" | "holding-register" | "holding-registers" | "hreg" | "hregs"
            | "register" | "registers" => Some(Self::Holding),
            "ir" | "input" | "input-register" | "input-registers" | "ireg" | "iregs" => {
                Some(Self::Input)
            }
            "co" | "coil" | "coils" => Some(Self::Coil),
            "di" | "discrete" | "discrete-input" | "discrete-inputs" | "input-bit"
            | "input-bits" => Some(Self::Discrete),
            _ => None,
        }
    }

    pub fn short_name(self) -> &'static str {
        match self {
            Self::Holding => "HR",
            Self::Input => "IR",
            Self::Coil => "CO",
            Self::Discrete => "DI",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Holding => "holding registers",
            Self::Input => "input registers",
            Self::Coil => "coils",
            Self::Discrete => "discrete inputs",
        }
    }

    pub fn point_type(self) -> &'static str {
        match self {
            Self::Holding | Self::Input => "UINT16",
            Self::Coil | Self::Discrete => "BOOL",
        }
    }

    pub fn chunk_limit(self) -> u16 {
        match self {
            Self::Holding | Self::Input => MODBUS_WORD_CHUNK,
            Self::Coil | Self::Discrete => MODBUS_BIT_CHUNK,
        }
    }

    pub fn display_addr(self, address: u32) -> u32 {
        let offset = match self {
            Self::Holding => 40001,
            Self::Input => 30001,
            Self::Coil => 1,
            Self::Discrete => 10001,
        };
        address + offset
    }

    pub fn point_key(self, address: u32) -> String {
        format!("{}{}", self.short_name(), self.display_addr(address))
    }
}

// ─── ModbusMapRange ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModbusMapRange {
    pub table: ModbusTable,
    pub start: u32,
    pub count: u32,
}

impl ModbusMapRange {
    pub fn new(table: ModbusTable, start: u32, count: u32) -> Self {
        Self {
            table,
            start,
            count,
        }
    }

    pub fn display_start(self) -> u32 {
        self.table.display_addr(self.start)
    }

    pub fn display_end(self) -> u32 {
        self.table.display_addr(self.start + self.count - 1)
    }
}

pub fn quick_modbus_ranges() -> Vec<ModbusMapRange> {
    vec![
        ModbusMapRange::new(ModbusTable::Holding, 0, 32),
        ModbusMapRange::new(ModbusTable::Input, 0, 32),
        ModbusMapRange::new(ModbusTable::Coil, 0, 64),
        ModbusMapRange::new(ModbusTable::Discrete, 0, 64),
    ]
}

pub fn common_modbus_ranges() -> Vec<ModbusMapRange> {
    vec![
        ModbusMapRange::new(ModbusTable::Holding, 0, 1000),
        ModbusMapRange::new(ModbusTable::Input, 0, 1000),
        ModbusMapRange::new(ModbusTable::Coil, 0, 2000),
        ModbusMapRange::new(ModbusTable::Discrete, 0, 2000),
    ]
}

pub fn all_modbus_ranges() -> Vec<ModbusMapRange> {
    vec![
        ModbusMapRange::new(ModbusTable::Holding, 0, MODBUS_ADDRESS_SPACE),
        ModbusMapRange::new(ModbusTable::Input, 0, MODBUS_ADDRESS_SPACE),
        ModbusMapRange::new(ModbusTable::Coil, 0, MODBUS_ADDRESS_SPACE),
        ModbusMapRange::new(ModbusTable::Discrete, 0, MODBUS_ADDRESS_SPACE),
    ]
}

pub fn parse_modbus_map_input(input: &str) -> Result<Vec<ModbusMapRange>, String> {
    let spec = input.trim();
    if spec.is_empty() || spec.eq_ignore_ascii_case("quick") {
        return Ok(quick_modbus_ranges());
    }
    if spec.eq_ignore_ascii_case("common") {
        return Ok(common_modbus_ranges());
    }
    if spec.eq_ignore_ascii_case("all") {
        return Ok(all_modbus_ranges());
    }
    let mut ranges = Vec::new();
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(format_modbus_map_usage());
        }
        let parts: Vec<_> = token.split(':').map(str::trim).collect();
        if parts.len() != 3 {
            return Err(format_modbus_map_usage());
        }
        let table = ModbusTable::parse(parts[0]).ok_or_else(|| {
            format!(
                "unknown Modbus table '{}'. {}",
                parts[0],
                format_modbus_map_usage()
            )
        })?;
        let start = parts[1].parse::<u32>().map_err(|_| {
            format!(
                "invalid start address '{}'. {}",
                parts[1],
                format_modbus_map_usage()
            )
        })?;
        let count = parts[2].parse::<u32>().map_err(|_| {
            format!(
                "invalid count '{}'. {}",
                parts[2],
                format_modbus_map_usage()
            )
        })?;
        if start >= MODBUS_ADDRESS_SPACE {
            return Err(format!(
                "start address {start} is outside 0..65535. {}",
                format_modbus_map_usage()
            ));
        }
        if count == 0 || count > MODBUS_ADDRESS_SPACE - start {
            return Err(format!(
                "count {count} at start {start} is outside the Modbus address space. {}",
                format_modbus_map_usage()
            ));
        }
        ranges.push(ModbusMapRange::new(table, start, count));
    }
    if ranges.is_empty() {
        Err(format_modbus_map_usage())
    } else {
        Ok(ranges)
    }
}

pub fn format_modbus_map_usage() -> String {
    "use quick, common, all, or table:start:count entries like hr:0:500,ir:0:100,co:0:128,di:0:128"
        .to_string()
}

/// Narrow an address or length that the range parsers already validated into 16 bits.
///
/// `parse_modbus_map_input` rejects spans that leave the protocol address space, so a
/// range that reaches the chunker always fits. This panics instead of clamping: the old
/// `unwrap_or(u16::MAX)` silently read the wrong addresses and looked like a normal chunk.
fn narrow16(value: u32) -> u16 {
    u16::try_from(value).expect("address range escaped the 16-bit space")
}

pub fn modbus_map_chunks(range: ModbusMapRange) -> Vec<(u16, u16)> {
    let mut chunks = Vec::new();
    let mut start = range.start;
    let mut remaining = range.count;
    let max_count = u32::from(range.table.chunk_limit());
    while remaining > 0 {
        let count = remaining.min(max_count);
        chunks.push((narrow16(start), narrow16(count)));
        start += count;
        remaining -= count;
    }
    chunks
}

// ─── SlmpDeviceKind / SlmpMapRange ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlmpDeviceKind {
    Word,
    Bit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlmpMapRange {
    pub device: &'static str,
    pub kind: SlmpDeviceKind,
    pub start: u32,
    pub count: u32,
}

impl SlmpMapRange {
    pub fn new(device: &'static str, kind: SlmpDeviceKind, start: u32, count: u32) -> Self {
        Self {
            device,
            kind,
            start,
            count,
        }
    }

    pub fn display_start(self) -> String {
        format!("{}{}", self.device, self.start)
    }

    pub fn display_end(self) -> String {
        format!("{}{}", self.device, self.start + self.count - 1)
    }

    pub fn chunk_limit(self) -> u16 {
        match self.kind {
            SlmpDeviceKind::Word => SLMP_WORD_CHUNK,
            SlmpDeviceKind::Bit => SLMP_BIT_CHUNK,
        }
    }
}

pub fn parse_slmp_device(input: &str) -> Option<(&'static str, SlmpDeviceKind)> {
    match input.trim().to_ascii_lowercase().as_str() {
        "d" | "data" | "data-register" | "data-registers" => Some(("D", SlmpDeviceKind::Word)),
        "w" | "link-register" | "link-registers" => Some(("W", SlmpDeviceKind::Word)),
        "r" | "file-register" | "file-registers" => Some(("R", SlmpDeviceKind::Word)),
        "m" | "marker" | "markers" | "internal-relay" | "internal-relays" => {
            Some(("M", SlmpDeviceKind::Bit))
        }
        "x" | "input" | "inputs" => Some(("X", SlmpDeviceKind::Bit)),
        "y" | "output" | "outputs" => Some(("Y", SlmpDeviceKind::Bit)),
        "b" | "link-relay" | "link-relays" => Some(("B", SlmpDeviceKind::Bit)),
        _ => None,
    }
}

pub fn quick_slmp_ranges() -> Vec<SlmpMapRange> {
    vec![
        SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, 50),
        SlmpMapRange::new("M", SlmpDeviceKind::Bit, 0, 128),
    ]
}

pub fn common_slmp_ranges() -> Vec<SlmpMapRange> {
    vec![
        SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, 1000),
        SlmpMapRange::new("W", SlmpDeviceKind::Word, 0, 512),
        SlmpMapRange::new("R", SlmpDeviceKind::Word, 0, 512),
        SlmpMapRange::new("M", SlmpDeviceKind::Bit, 0, 2048),
        SlmpMapRange::new("X", SlmpDeviceKind::Bit, 0, 512),
        SlmpMapRange::new("Y", SlmpDeviceKind::Bit, 0, 512),
        SlmpMapRange::new("B", SlmpDeviceKind::Bit, 0, 512),
    ]
}

pub fn all_slmp_ranges() -> Vec<SlmpMapRange> {
    vec![
        SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, SLMP_ADDRESS_SPACE),
        SlmpMapRange::new("W", SlmpDeviceKind::Word, 0, SLMP_ADDRESS_SPACE),
        SlmpMapRange::new("R", SlmpDeviceKind::Word, 0, SLMP_ADDRESS_SPACE),
        SlmpMapRange::new("M", SlmpDeviceKind::Bit, 0, SLMP_ADDRESS_SPACE),
        SlmpMapRange::new("X", SlmpDeviceKind::Bit, 0, SLMP_ADDRESS_SPACE),
        SlmpMapRange::new("Y", SlmpDeviceKind::Bit, 0, SLMP_ADDRESS_SPACE),
        SlmpMapRange::new("B", SlmpDeviceKind::Bit, 0, SLMP_ADDRESS_SPACE),
    ]
}

pub fn parse_slmp_map_input(input: &str) -> Result<Vec<SlmpMapRange>, String> {
    let spec = input.trim();
    if spec.is_empty() || spec.eq_ignore_ascii_case("quick") {
        return Ok(quick_slmp_ranges());
    }
    if spec.eq_ignore_ascii_case("common") {
        return Ok(common_slmp_ranges());
    }
    if spec.eq_ignore_ascii_case("all") {
        return Ok(all_slmp_ranges());
    }
    let mut ranges = Vec::new();
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(format_slmp_map_usage());
        }
        let parts: Vec<_> = token.split(':').map(str::trim).collect();
        if parts.len() != 3 {
            return Err(format_slmp_map_usage());
        }
        let (device, kind) = parse_slmp_device(parts[0]).ok_or_else(|| {
            format!(
                "unknown SLMP device '{}'. {}",
                parts[0],
                format_slmp_map_usage()
            )
        })?;
        let start = parts[1].parse::<u32>().map_err(|_| {
            format!(
                "invalid start address '{}'. {}",
                parts[1],
                format_slmp_map_usage()
            )
        })?;
        let count = parts[2]
            .parse::<u32>()
            .map_err(|_| format!("invalid count '{}'. {}", parts[2], format_slmp_map_usage()))?;
        if start >= SLMP_ADDRESS_SPACE {
            return Err(format!(
                "start address {start} is outside 0..16777215. {}",
                format_slmp_map_usage()
            ));
        }
        if count == 0 || count > SLMP_ADDRESS_SPACE - start {
            return Err(format!(
                "count {count} at start {start} is outside the SLMP address space. {}",
                format_slmp_map_usage()
            ));
        }
        ranges.push(SlmpMapRange::new(device, kind, start, count));
    }
    if ranges.is_empty() {
        Err(format_slmp_map_usage())
    } else {
        Ok(ranges)
    }
}

pub fn format_slmp_map_usage() -> String {
    "use quick, common, all, or device:start:count entries like d:0:100,m:0:128,w:0:64".to_string()
}

pub fn slmp_map_chunks(range: SlmpMapRange) -> Vec<(u32, u16)> {
    let mut chunks = Vec::new();
    let mut start = range.start;
    let mut remaining = range.count;
    let max_count = u32::from(range.chunk_limit());
    while remaining > 0 {
        let count = remaining.min(max_count);
        chunks.push((start, u16::try_from(count).unwrap_or(u16::MAX)));
        start += count;
        remaining -= count;
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ModbusTable -------------------------------------------------------

    #[test]
    fn modbus_table_parsing_accepts_every_documented_alias() {
        for alias in [
            "hr",
            "holding",
            "holding-register",
            "holding-registers",
            "HREG",
        ] {
            assert_eq!(
                ModbusTable::parse(alias),
                Some(ModbusTable::Holding),
                "alias {alias} should be holding registers"
            );
        }
        for alias in ["ir", "input", "input-register", "input-registers"] {
            assert_eq!(
                ModbusTable::parse(alias),
                Some(ModbusTable::Input),
                "alias {alias} should be input registers"
            );
        }
        for alias in ["co", "coil", "coils"] {
            assert_eq!(
                ModbusTable::parse(alias),
                Some(ModbusTable::Coil),
                "alias {alias} should be coils"
            );
        }
        for alias in ["di", "discrete", "discrete-inputs", "input-bits"] {
            assert_eq!(
                ModbusTable::parse(alias),
                Some(ModbusTable::Discrete),
                "alias {alias} should be discrete inputs"
            );
        }
        assert_eq!(ModbusTable::parse("  HR  "), Some(ModbusTable::Holding));
        assert_eq!(ModbusTable::parse("register-holding"), None);
        assert_eq!(ModbusTable::parse(""), None);
    }

    #[test]
    fn modbus_display_addresses_match_the_plc_conventions() {
        assert_eq!(ModbusTable::Holding.display_addr(0), 40001);
        assert_eq!(ModbusTable::Input.display_addr(0), 30001);
        assert_eq!(ModbusTable::Coil.display_addr(0), 1);
        assert_eq!(ModbusTable::Discrete.display_addr(0), 10001);
    }

    #[test]
    fn modbus_point_keys_use_the_short_prefix() {
        assert_eq!(ModbusTable::Holding.point_key(7), "HR40008");
        assert_eq!(ModbusTable::Coil.point_key(0), "CO1");
    }

    #[test]
    fn modbus_point_type_follows_the_table_width() {
        assert_eq!(ModbusTable::Holding.point_type(), "UINT16");
        assert_eq!(ModbusTable::Input.point_type(), "UINT16");
        assert_eq!(ModbusTable::Coil.point_type(), "BOOL");
        assert_eq!(ModbusTable::Discrete.point_type(), "BOOL");
    }

    // --- parse_modbus_map_input -------------------------------------------

    #[test]
    fn empty_and_quick_specs_both_mean_quick() {
        let quick = quick_modbus_ranges();
        assert_eq!(parse_modbus_map_input("").expect("empty is quick"), quick);
        assert_eq!(parse_modbus_map_input("  ").expect("blank is quick"), quick);
        assert_eq!(
            parse_modbus_map_input("QUICK").expect("quick keyword"),
            quick
        );
    }

    #[test]
    fn named_specs_expand_to_their_tables() {
        assert_eq!(
            parse_modbus_map_input("common").expect("common keyword"),
            common_modbus_ranges()
        );
        assert_eq!(
            parse_modbus_map_input("all").expect("all keyword"),
            all_modbus_ranges()
        );
    }

    #[test]
    fn explicit_specs_keep_order_and_tables() {
        let ranges =
            parse_modbus_map_input("hr:0:500,ir:10:20,co:5:6,di:7:8").expect("four valid ranges");
        assert_eq!(ranges.len(), 4);
        assert_eq!(ranges[0], ModbusMapRange::new(ModbusTable::Holding, 0, 500));
        assert_eq!(ranges[1], ModbusMapRange::new(ModbusTable::Input, 10, 20));
        assert_eq!(ranges[2], ModbusMapRange::new(ModbusTable::Coil, 5, 6));
        assert_eq!(ranges[3], ModbusMapRange::new(ModbusTable::Discrete, 7, 8));
    }

    #[test]
    fn map_range_display_end_is_inclusive() {
        let range = ModbusMapRange::new(ModbusTable::Holding, 0, 32);
        assert_eq!(range.display_start(), 40001);
        assert_eq!(range.display_end(), 40032);
    }

    #[test]
    fn bad_modbus_specs_name_the_offending_field() {
        let unknown_table = parse_modbus_map_input("zz:0:1").expect_err("unknown table");
        assert!(
            unknown_table.contains("unknown Modbus table 'zz'"),
            "error should quote the table: {unknown_table}"
        );

        let bad_start = parse_modbus_map_input("hr:x:1").expect_err("non numeric start");
        assert!(
            bad_start.contains("invalid start address 'x'"),
            "error should quote the start: {bad_start}"
        );

        let bad_count = parse_modbus_map_input("hr:0:y").expect_err("non numeric count");
        assert!(
            bad_count.contains("invalid count 'y'"),
            "error should quote the count: {bad_count}"
        );

        let zero_count = parse_modbus_map_input("hr:0:0").expect_err("zero count");
        assert!(
            zero_count.contains("outside the Modbus address space"),
            "zero count must be rejected: {zero_count}"
        );

        for spec in ["hr:0", "hr:0:1:2", ",", "hr:0:1,"] {
            assert!(
                parse_modbus_map_input(spec).is_err(),
                "spec {spec:?} should be rejected"
            );
        }
    }

    #[test]
    fn modbus_spec_may_use_the_whole_address_space_but_not_more() {
        let whole = parse_modbus_map_input("hr:0:65536").expect("the full address space");
        assert_eq!(
            whole,
            vec![ModbusMapRange::new(ModbusTable::Holding, 0, 65_536)]
        );
        assert!(parse_modbus_map_input("hr:0:65537").is_err());
        assert!(parse_modbus_map_input("hr:65536:1").is_err());
        assert!(parse_modbus_map_input("hr:65535:1").is_ok());
    }

    // --- modbus_map_chunks ------------------------------------------------

    #[test]
    fn modbus_chunks_respect_the_per_table_limit() {
        let words = ModbusMapRange::new(ModbusTable::Holding, 0, 300);
        assert_eq!(
            modbus_map_chunks(words),
            vec![(0, 125), (125, 125), (250, 50)],
            "words split at 125 and keep the remainder"
        );

        let bits = ModbusMapRange::new(ModbusTable::Coil, 0, 4000);
        assert_eq!(
            modbus_map_chunks(bits),
            vec![(0, 2000), (2000, 2000)],
            "coils split at 2000"
        );
    }

    #[test]
    fn modbus_chunks_are_empty_only_for_an_empty_range() {
        let empty = ModbusMapRange::new(ModbusTable::Holding, 0, 0);
        assert!(
            modbus_map_chunks(empty).is_empty(),
            "expected empty, got {:?}",
            modbus_map_chunks(empty)
        );

        let single = ModbusMapRange::new(ModbusTable::Discrete, 17, 1);
        assert_eq!(modbus_map_chunks(single), vec![(17, 1)]);
    }

    // --- SLMP -------------------------------------------------------------

    #[test]
    fn slmp_device_names_map_to_their_register_class() {
        assert_eq!(
            parse_slmp_device("d"),
            Some(("D", SlmpDeviceKind::Word)),
            "D is a word device"
        );
        assert_eq!(
            parse_slmp_device("MARKERS"),
            Some(("M", SlmpDeviceKind::Bit)),
            "M is a bit device"
        );
        assert_eq!(
            parse_slmp_device("link-relays"),
            Some(("B", SlmpDeviceKind::Bit))
        );
        assert_eq!(parse_slmp_device("q"), None);
    }

    #[test]
    fn slmp_specs_parse_and_reject_the_same_way_modbus_does() {
        let ranges = parse_slmp_map_input("d:0:100,m:0:128").expect("two valid ranges");
        assert_eq!(ranges.len(), 2);
        assert_eq!(
            ranges[0],
            SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, 100)
        );
        assert_eq!(
            ranges[1],
            SlmpMapRange::new("M", SlmpDeviceKind::Bit, 0, 128)
        );

        let unknown = parse_slmp_map_input("q:0:1").expect_err("unknown device");
        assert!(
            unknown.contains("unknown SLMP device 'q'"),
            "error should quote the device: {unknown}"
        );
        assert!(parse_slmp_map_input("d:0:0").is_err(), "zero count");
        assert!(
            parse_slmp_map_input("d:16777216:1").is_err(),
            "start outside the SLMP space"
        );
    }

    #[test]
    fn slmp_chunks_respect_the_per_device_limit() {
        let word = SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, 2000);
        assert_eq!(
            slmp_map_chunks(word),
            vec![(0, 960), (960, 960), (1920, 80)],
            "word devices split at 960"
        );

        let bit = SlmpMapRange::new("M", SlmpDeviceKind::Bit, 0, 4000);
        assert_eq!(
            slmp_map_chunks(bit),
            vec![(0, 3584), (3584, 416)],
            "bit devices split at 3584"
        );
    }

    #[test]
    fn slmp_display_addresses_join_the_device_prefix() {
        let range = SlmpMapRange::new("D", SlmpDeviceKind::Word, 10, 5);
        assert_eq!(range.display_start(), "D10");
        assert_eq!(range.display_end(), "D14");
    }
}
