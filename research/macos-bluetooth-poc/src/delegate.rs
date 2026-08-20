//! Obj-C delegate that receives IOBluetooth's RFCOMM channel + data callbacks and funnels what the camera sends into
//! shared globals the main flow polls.
use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{mem, slice};

use objc2::define_class;
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_foundation::{NSObject, NSObjectProtocol};
use objc2_io_bluetooth::IOBluetoothRFCOMMChannel;

use crate::log::step;

/// Bytes of each received frame to hex-preview in the log.
const PREVIEW_BYTES: usize = 32;

// Delegate -> main communication.
pub(crate) static RECV: Mutex<Vec<u8>> = Mutex::new(Vec::new());
pub(crate) static GOT_CHANNEL: AtomicBool = AtomicBool::new(false);

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "GearSapDelegate"]
    pub(crate) struct GearSapDelegate;

    unsafe impl NSObjectProtocol for GearSapDelegate {}

    impl GearSapDelegate {
        // Notification target, called when any RFCOMM channel opens.
        // ObjC selector: -(void)x:(IOBluetoothUserNotification*)n channel:(IOBluetoothRFCOMMChannel*)c
        #[unsafe(method(rfcommChannelOpened:channel:))]
        fn rfcomm_channel_opened(
            &self,
            _notification: *mut AnyObject,
            channel: &IOBluetoothRFCOMMChannel,
        ) {
            let channel_id = unsafe { channel.getChannelID() };
            let incoming = unsafe { channel.isIncoming() };
            step!("[delegate] RFCOMM channel opened (id={channel_id}, incoming={incoming})");

            // Become the channel's data listener so the open handshake completes.
            let delegate_ref: &AnyObject = unsafe { &*(self as *const Self as *const AnyObject) };
            unsafe { channel.setDelegate(Some(delegate_ref)) };

            // Leak a retain so the channel outlives this callback for the session.
            let channel_ptr =
                channel as *const IOBluetoothRFCOMMChannel as *mut IOBluetoothRFCOMMChannel;
            // Channel is a valid, live IOBluetoothRFCOMMChannel here.
            if let Some(retained) = unsafe { Retained::retain(channel_ptr) } {
                mem::forget(retained);
            }
            GOT_CHANNEL.store(true, Ordering::SeqCst);
        }

        #[unsafe(method(rfcommChannelData:data:length:))]
        fn rfcomm_channel_data(&self, _channel: *mut AnyObject, data: *mut c_void, length: usize) {
            // IOBluetooth passes a valid `data`/`length` pair for this callback.
            let bytes = unsafe { slice::from_raw_parts(data as *const u8, length) };
            step!("[delegate] RX {length} bytes: {:02x?}", &bytes[..length.min(PREVIEW_BYTES)]);
            RECV.lock().unwrap().extend_from_slice(bytes);
        }

        #[unsafe(method(rfcommChannelOpenComplete:status:))]
        fn rfcomm_open_complete(&self, _channel: *mut AnyObject, status: i32) {
            step!("[delegate] open complete (status={status})");
        }

        #[unsafe(method(rfcommChannelClosed:))]
        fn rfcomm_channel_closed(&self, _channel: *mut AnyObject) {
            step!("[delegate] channel closed");
        }
    }
);
