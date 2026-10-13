pub mod nostr_stack;

// This helper is shared by harness binaries; only message-delivery tests use it.
#[allow(dead_code)]
pub fn received_sender_device(
    work: &cgka_session::PublishWork,
) -> cgka_traits::message::SenderDevice {
    use cgka_traits::message::SenderDevice;
    let cgka_session::PublishWork::ApplicationMessage { sender_device, .. } = work else {
        panic!("expected application publication");
    };
    let mut device = sender_device.clone();
    let SenderDevice::Exact {
        is_this_installation,
        ..
    } = &mut device
    else {
        panic!("fresh authenticated sends must identify their device");
    };
    assert!(*is_this_installation);
    *is_this_installation = false;
    device
}
