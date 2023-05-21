use super::device::DeviceType;

pub mod root_node;

pub const DEVICE_TYPE_EXTENDED_COLOR_LIGHT: DeviceType = DeviceType {
    device_type: 0x010d,
    device_revision: 2,
};
