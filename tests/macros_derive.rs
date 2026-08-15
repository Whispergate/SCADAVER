use scadaver::core::autodetect::IntoDeviceInfo as IntoDeviceInfoTrait;
use scadaver_macros::IntoDeviceInfo;

// Mirror of MqttDevice shape: String and Option<String> fields map through the macro;
// non-String fields (port, bool flags) use #[device_info(skip)].
#[derive(IntoDeviceInfo)]
#[vendor(slug = "mqtt")]
struct MockMqttDevice {
    #[device_info(ip)]
    ip: String,
    #[device_info(optional)]
    broker_info: Option<String>,
    #[device_info(skip)]
    _port: u16,
    #[device_info(skip)]
    _anonymous: bool,
    #[device_info(skip)]
    _sparkplug: bool,
}

#[derive(IntoDeviceInfo)]
#[vendor(slug = "acme")]
struct AcmeDevice {
    #[device_info(ip)]
    ip: String,
    model: String,
    firmware: String,
    #[device_info(optional)]
    serial: Option<String>,
    #[device_info(skip)]
    _state: u8,
    #[device_info(rename = "hw_revision")]
    revision: String,
}

#[test]
fn into_device_info_maps_fields() {
    let d = AcmeDevice {
        ip: "192.168.1.1".to_string(),
        model: "AcmePLC-200".to_string(),
        firmware: "3.1.4".to_string(),
        serial: Some("SN-0042".to_string()),
        _state: 7,
        revision: "rev-C".to_string(),
    };
    let info = d.into_device_info();
    assert_eq!(info.vendor, "acme");
    assert_eq!(info.ip, "192.168.1.1");
    assert_eq!(info.fields["model"], "AcmePLC-200");
    assert_eq!(info.fields["firmware"], "3.1.4");
    assert_eq!(info.fields["serial"], "SN-0042");
    assert_eq!(info.fields["hw_revision"], "rev-C");
    assert!(!info.fields.contains_key("_state"),   "skipped field must be absent");
    assert!(!info.fields.contains_key("revision"), "original name shadowed by rename must be absent");
    assert!(!info.fields.contains_key("ip"),       "ip field must not appear in fields map");
}

#[test]
fn optional_field_absent_when_none() {
    let d = AcmeDevice {
        ip: "10.0.0.1".to_string(),
        model: "AcmePLC-100".to_string(),
        firmware: "1.0.0".to_string(),
        serial: None,
        _state: 0,
        revision: "rev-A".to_string(),
    };
    let info = d.into_device_info();
    assert!(!info.fields.contains_key("serial"), "None optional must be absent from fields");
}

#[test]
fn vendor_slug_constant() {
    assert_eq!(AcmeDevice::VENDOR_SLUG, "acme");
}

#[test]
fn mqtt_device_into_device_info_via_macro() {
    let dev = MockMqttDevice {
        ip: "192.168.1.100".into(),
        broker_info: Some("mosquitto 2.0.18".into()),
        _port: 1883,
        _anonymous: true,
        _sparkplug: false,
    };
    let info = dev.into_device_info();
    assert_eq!(info.vendor, "mqtt");
    assert_eq!(info.ip, "192.168.1.100");
    assert_eq!(info.fields["broker_info"], "mosquitto 2.0.18");
    assert!(!info.fields.contains_key("_port"),      "skipped field must be absent");
    assert!(!info.fields.contains_key("_anonymous"), "skipped field must be absent");
    assert!(!info.fields.contains_key("_sparkplug"), "skipped field must be absent");
    assert!(!info.fields.contains_key("ip"),         "ip field must not appear in fields map");
}

#[test]
fn mqtt_device_broker_info_none_absent_from_fields() {
    let dev = MockMqttDevice {
        ip: "10.0.0.1".into(),
        broker_info: None,
        _port: 1883,
        _anonymous: false,
        _sparkplug: false,
    };
    let info = dev.into_device_info();
    assert!(!info.fields.contains_key("broker_info"), "None optional must be absent from fields");
}
