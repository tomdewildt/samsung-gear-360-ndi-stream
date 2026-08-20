//! SDP service-record construction: build the SAP service's property list and
//! parse it into the `NSDictionary` that IOBluetooth's publish call expects.

use base64::prelude::{BASE64_STANDARD, Engine as _};
use objc2::rc::Retained;
use objc2_foundation::{
    NSData, NSDictionary, NSPropertyListMutabilityOptions, NSPropertyListSerialization,
};

/// 128-bit SAP service UUID we publish.
const UUID_2: [u8; 16] = [
    0xa4, 0x9e, 0xb4, 0x1e, 0xcb, 0x06, 0x49, 0x5c, 0x9f, 0x4f, 0xaa, 0x80, 0xa9, 0x0c, 0xdf, 0x4a,
];

/// Build the SAP service's SDP record (UUID_2 over RFCOMM) as an `NSDictionary`.
pub(crate) fn build_sdp_dictionary() -> Retained<NSDictionary> {
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>0001 - ServiceClassIDList</key>
    <dict>
        <key>DataElementType</key><integer>6</integer>
        <key>DataElementValue</key>
        <array>
            <dict>
                <key>DataElementType</key><integer>3</integer>
                <key>DataElementSize</key><integer>16</integer>
                <key>DataElementValue</key><data>{uuid_b64}</data>
            </dict>
        </array>
    </dict>
    <key>0004 - ProtocolDescriptorList</key>
    <dict>
        <key>DataElementType</key><integer>6</integer>
        <key>DataElementValue</key>
        <array>
            <dict>
                <key>DataElementType</key><integer>6</integer>
                <key>DataElementValue</key>
                <array>
                    <dict>
                        <key>DataElementType</key><integer>3</integer>
                        <key>DataElementSize</key><integer>2</integer>
                        <key>DataElementValue</key><integer>256</integer>
                    </dict>
                </array>
            </dict>
            <dict>
                <key>DataElementType</key><integer>6</integer>
                <key>DataElementValue</key>
                <array>
                    <dict>
                        <key>DataElementType</key><integer>3</integer>
                        <key>DataElementSize</key><integer>2</integer>
                        <key>DataElementValue</key><integer>3</integer>
                    </dict>
                    <dict>
                        <key>DataElementType</key><integer>1</integer>
                        <key>DataElementSize</key><integer>1</integer>
                        <key>DataElementValue</key><integer>1</integer>
                    </dict>
                </array>
            </dict>
        </array>
    </dict>
    <key>0100 - ServiceName*</key>
    <dict>
        <key>DataElementType</key><integer>4</integer>
        <key>DataElementValue</key><string>Gear360 SAP</string>
    </dict>
</dict>
</plist>"#,
        uuid_b64 = BASE64_STANDARD.encode(UUID_2),
    );

    parse_plist(&plist)
}

/// Parse an XML property-list string into an `NSDictionary` (panics if malformed).
pub(crate) fn parse_plist(xml: &str) -> Retained<NSDictionary> {
    let data = NSData::with_bytes(xml.as_bytes());
    let object = unsafe {
        NSPropertyListSerialization::propertyListWithData_options_format_error(
            &data,
            NSPropertyListMutabilityOptions(0),
            std::ptr::null_mut(),
        )
    }
    .expect("plist parse failed");
    object
        .downcast::<NSDictionary>()
        .expect("plist is not a dict")
}

/// Stock Serial-Port-Profile record (16-bit UUID 0x1101) used for the publish probe.
pub(crate) const SPP_PROBE_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>0001 - ServiceClassIDList</key>
    <dict>
        <key>DataElementType</key><integer>6</integer>
        <key>DataElementValue</key>
        <array>
            <dict>
                <key>DataElementType</key><integer>3</integer>
                <key>DataElementSize</key><integer>2</integer>
                <key>DataElementValue</key><integer>4353</integer>
            </dict>
        </array>
    </dict>
    <key>0004 - ProtocolDescriptorList</key>
    <dict>
        <key>DataElementType</key><integer>6</integer>
        <key>DataElementValue</key>
        <array>
            <dict>
                <key>DataElementType</key><integer>6</integer>
                <key>DataElementValue</key>
                <array>
                    <dict>
                        <key>DataElementType</key><integer>3</integer>
                        <key>DataElementSize</key><integer>2</integer>
                        <key>DataElementValue</key><integer>256</integer>
                    </dict>
                </array>
            </dict>
            <dict>
                <key>DataElementType</key><integer>6</integer>
                <key>DataElementValue</key>
                <array>
                    <dict>
                        <key>DataElementType</key><integer>3</integer>
                        <key>DataElementSize</key><integer>2</integer>
                        <key>DataElementValue</key><integer>3</integer>
                    </dict>
                    <dict>
                        <key>DataElementType</key><integer>1</integer>
                        <key>DataElementSize</key><integer>1</integer>
                        <key>DataElementValue</key><integer>1</integer>
                    </dict>
                </array>
            </dict>
        </array>
    </dict>
</dict>
</plist>"#;
