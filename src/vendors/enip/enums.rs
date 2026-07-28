use std::collections::HashMap;

pub fn device_type_name(id: u32) -> String {
    let map: HashMap<u32, &str> = [
        (0, "Generic Device (deprecated)"),
        (2, "AC Drive"),
        (3, "Motor Overload"),
        (4, "Limit Switch"),
        (5, "Inductive Proximity Switch"),
        (6, "Photoelectric Sensor"),
        (7, "General Purpose Discrete I/O"),
        (9, "Resolver"),
        (12, "Communications Adapter"),
        (14, "Programmable Logic Controller"),
        (16, "Position Controller"),
        (19, "DC Drive"),
        (21, "Contactor"),
        (22, "Motor Starter"),
        (23, "Soft Start"),
        (24, "Human-Machine Interface"),
        (26, "Mass Flow Controller"),
        (27, "Pneumatic Valve"),
        (28, "Vacuum Pressure Gauge"),
        (29, "Process Control Value"),
        (30, "Residual Gas Analyzer"),
        (31, "DC Power Generator"),
        (32, "RF Power Generator"),
        (33, "Turbomolecular Vacuum Pump"),
        (34, "Encoder"),
        (35, "Safety Discrete I/O Device"),
        (36, "Fluid Flow Controller"),
        (37, "CIP Motion Drive"),
        (38, "CompoNet Repeater"),
        (39, "Mass Flow Controller Enhanced"),
        (40, "CIP Modbus Device"),
        (41, "CIP Modbus Translator"),
        (42, "Safety Analog I/O Device"),
        (43, "Generic Device (keyable)"),
        (44, "Managed Switch"),
        (59, "ControlNet Physical Layer Component"),
    ]
    .into_iter()
    .collect();

    map.get(&id).map_or_else(|| format!("Unknown ({id})"), |s| (*s).to_string())
}

pub fn vendor_name(id: u32) -> String {
    let map: HashMap<u32, &str> = [
        (0, "Reserved"),
        (1, "Rockwell Automation/Allen-Bradley"),
        (2, "Namco Controls Corp."),
        (3, "Honeywell Inc."),
        (4, "Parker Hannifin Corp."),
        (5, "Rockwell Automation/Reliance Elec."),
        (6, "Reserved"),
        (7, "SMC Corporation"),
        (8, "Molex Incorporated"),
        (10, "Grayhill Inc."),
        (12, "Numatics Inc."),
        (14, "Festo Corporation"),
        (15, "Reserved"),
        (19, "Turck Inc."),
        (24, "Cognex Corporation"),
        (30, "Omron Corporation"),
        (36, "Mitsubishi Electric Automation"),
        (40, "Schneider Automation Inc."),
        (48, "Pepperl+Fuchs"),
        (77, "Rockwell Software Inc."),
        (100, "Siemens Energy & Automation"),
        (120, "Phoenix Contact"),
        (315, "Beckhoff Automation GmbH"),
        (1093, "HMS Networks"),
        (1178, "Moxa Inc."),
    ]
    .into_iter()
    .collect();

    map.get(&id).map_or_else(|| format!("Unknown ({id})"), |s| (*s).to_string())
}
