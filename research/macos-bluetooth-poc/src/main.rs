mod delegate;
mod log;
mod sdp;

use std::mem;
use std::sync::atomic::Ordering;

use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{AllocAnyThread, sel};
use objc2_core_foundation::{CFRunLoop, kCFRunLoopDefaultMode};
use objc2_io_bluetooth::{
    IOBluetoothDevice, IOBluetoothHostController, IOBluetoothRFCOMMChannel,
    IOBluetoothSDPServiceRecord,
};

use crate::delegate::{GOT_CHANNEL, GearSapDelegate, RECV};
use crate::log::step;
use crate::sdp::{SPP_PROBE_PLIST, build_sdp_dictionary, parse_plist};

const CAMERA_MAC_DASH: &str = "c8-38-70-3f-97-75"; // HARDCODED: camera BT MAC address

/// First byte of a SAP PD_REQUEST (the sign the camera is talking to us).
const PD_REQUEST: u8 = 0x05;
/// Highest RFCOMM channel to try when brute-forcing outbound.
const MAX_RFCOMM_CHANNEL: u8 = 30;
/// Run-loop pump interval, in seconds.
const POLL_SECONDS: f64 = 0.1;
/// Run-loop pumps to warm up the bluetoothd connection before publishing.
const WARMUP_POLLS: usize = 5;
/// Run-loop pumps (~2.5s) to wait for SAP data on an opened outbound channel.
const OUTBOUND_DATA_POLLS: usize = 25;
/// Run-loop pumps (~30s) to wait for the camera to connect back.
const CONNECT_BACK_POLLS: usize = 300;

fn main() {
    wake_bluetooth_daemon();
    probe_spp_publish();
    publish_sap_service();

    let delegate: Retained<GearSapDelegate> =
        unsafe { objc2::msg_send![GearSapDelegate::alloc(), init] };
    // Delegate stays alive for the rest of main, outliving this borrow.
    let delegate_ref: &AnyObject =
        unsafe { &*(&*delegate as *const GearSapDelegate as *const AnyObject) };

    if !register_inbound_notifications(delegate_ref) {
        return;
    }
    probe_outbound_channels(delegate_ref);
    wait_for_connect_back();
}

/// Pump the CoreFoundation run loop once so queued Bluetooth callbacks can fire.
fn pump_run_loop() {
    unsafe { CFRunLoop::run_in_mode(kCFRunLoopDefaultMode, POLL_SECONDS, false) };
}

/// Wake the IOBluetooth framework's link to bluetoothd before publishing; the first SDP call otherwise races the
/// daemon connection and silently no-ops.
fn wake_bluetooth_daemon() {
    match unsafe { IOBluetoothHostController::defaultController() } {
        Some(controller) => {
            let address = unsafe { controller.addressAsString() }
                .map(|s| s.to_string())
                .unwrap_or_default();
            println!("Host controller: {address}");
        }
        None => println!("No default host controller!"),
    }
    for _ in 0..WARMUP_POLLS {
        pump_run_loop();
    }
}

/// Try to publish a stock Serial-Port-Profile service. On modern macOS this returns nil even for plain SPP. The core
/// finding that third-party  SDP-server publishing is broken, so the camera's connect-back can't be hosted.
fn probe_spp_publish() {
    let spp_dict = parse_plist(SPP_PROBE_PLIST);
    let record = unsafe {
        IOBluetoothSDPServiceRecord::publishedServiceRecordWithDictionary(Some(&spp_dict))
    };
    let outcome = if record.is_some() {
        "OK"
    } else {
        "nil (broken on modern macOS)"
    };
    println!("PROBE: SPP publishedServiceRecordWithDictionary -> {outcome}");
}

/// Publish our UUID_2 SAP service so the camera can discover our RFCOMM channel. Expected to fail on modern macOS
/// (see [`probe_spp_publish`]). We continue anyway to exercise the outbound-channel path.
fn publish_sap_service() {
    println!("Publishing UUID_2 SDP service...");
    let service_dict = build_sdp_dictionary();
    step!(
        "Parsed SDP dictionary with {} top-level keys",
        service_dict.count()
    );

    let record = unsafe {
        IOBluetoothSDPServiceRecord::publishedServiceRecordWithDictionary(Some(&service_dict))
    };
    match &record {
        Some(published) => {
            let mut channel_id: u8 = 0;
            let _ = unsafe { published.getRFCOMMChannelID(&mut channel_id) };
            step!("Published. Assigned RFCOMM channel: {channel_id}");
        }
        None => step!("Publish FAILED (continuing anyway to test outbound channel)."),
    }
}

/// Register for inbound RFCOMM channel-open notifications, routed to delegate. Returns false if registration fails,
/// in which case nothing else can work.
fn register_inbound_notifications(delegate: &AnyObject) -> bool {
    println!("Registering for inbound RFCOMM channel notifications...");
    let notification = unsafe {
        IOBluetoothRFCOMMChannel::registerForChannelOpenNotifications_selector(
            Some(delegate),
            Some(sel!(rfcommChannelOpened:channel:)),
        )
    };
    if notification.is_none() {
        step!("FAILED to register notification.");
        return false;
    }
    true
}

/// Brute-force outbound RFCOMM channels, since the camera's SDP is unreadable here. If it speaks SAP over a channel we
/// open, we never need the (impossible) server role at all.
fn probe_outbound_channels(delegate: &AnyObject) {
    println!(
        "Probing outbound RFCOMM channels 1..{MAX_RFCOMM_CHANNEL} (open, wait for SAP data)..."
    );
    let Some(camera) = find_camera() else {
        step!("Camera not found in paired devices.");
        return;
    };

    for channel_id in 1..=MAX_RFCOMM_CHANNEL {
        let mut channel: Option<Retained<IOBluetoothRFCOMMChannel>> = None;
        RECV.lock().unwrap().clear();
        let open_result = unsafe {
            camera.openRFCOMMChannelSync_withChannelID_delegate(
                Some(&mut channel),
                channel_id,
                Some(delegate),
            )
        };
        let Some(channel) = channel.filter(|_| open_result == 0) else {
            step!("ch {channel_id}: open failed (rc={open_result})");
            continue;
        };

        if wait_for_data(OUTBOUND_DATA_POLLS) {
            let received = RECV.lock().unwrap();
            step!(
                "ch {channel_id}: OPENED + {} bytes! first=0x{:02x} (PD_REQUEST=0x{PD_REQUEST:02x})",
                received.len(),
                received[0],
            );
            drop(received);
            mem::forget(channel); // Keep the working channel alive
            return;
        }
        step!("ch {channel_id}: opened but silent — closing");
        unsafe { channel.closeChannel() };
    }
    step!("No channel produced SAP data.");
}

/// Pump the run loop up to `max_polls` times, returning true as soon as the delegate has buffered any received bytes.
fn wait_for_data(max_polls: usize) -> bool {
    for _ in 0..max_polls {
        pump_run_loop();
        if !RECV.lock().unwrap().is_empty() {
            return true;
        }
    }
    false
}

/// Run the loop waiting for the camera to connect back to our service and send data. The capability the whole poc
/// exists to test.
fn wait_for_connect_back() {
    let timeout_seconds = (CONNECT_BACK_POLLS as f64 * POLL_SECONDS) as u64;
    println!(
        "\nWaiting up to {timeout_seconds}s for the camera to connect back and send data...\n"
    );

    for _ in 0..CONNECT_BACK_POLLS {
        pump_run_loop();
        if GOT_CHANNEL.load(Ordering::SeqCst) && !RECV.lock().unwrap().is_empty() {
            let received = RECV.lock().unwrap();
            println!(
                "\nSUCCESS: received {} bytes. First byte = 0x{:02x} (PD_REQUEST=0x{PD_REQUEST:02x}).",
                received.len(),
                received[0],
            );
            return;
        }
    }

    if GOT_CHANNEL.load(Ordering::SeqCst) {
        println!("\nChannel opened but no data arrived.");
    } else {
        println!("\nTimed out: no inbound RFCOMM channel from the camera.");
    }
}

/// Look up the paired Gear 360 by its MAC and return a retained handle.
fn find_camera() -> Option<Retained<IOBluetoothDevice>> {
    let devices = unsafe { IOBluetoothDevice::pairedDevices() }?;
    for element in devices.iter() {
        let device = element.downcast_ref::<IOBluetoothDevice>()?;
        let address = unsafe { device.addressString() }.map(|s| s.to_string());
        if address.as_deref() == Some(CAMERA_MAC_DASH) {
            let device_ptr = device as *const IOBluetoothDevice as *mut IOBluetoothDevice;
            // SAFETY: `device` is a live entry in the paired-devices array.
            return unsafe { Retained::retain(device_ptr) };
        }
    }
    None
}
