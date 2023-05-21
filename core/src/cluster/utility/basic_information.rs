use num::FromPrimitive;

use crate::{
    cluster::{Cluster, ClusterClassification},
    data_model::{
        handler::{AttrDataEncoder, Handler},
        Attribute,
    },
    interaction_model::{AttributeDataIB, AttributePathIB},
    tlv::Encoder,
};

pub const CLUSTER_ID: u16 = 0x0028;

pub const CLUSTER: Cluster<'static> = Cluster {
    id: CLUSTER_ID,
    classification: ClusterClassification::Utility,
    revision: 1,
    features: 0,
    attributes: &[
        Attribute {
            id: Attributes::DataModelRevision as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::VendorName as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::VendorID as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::ProductName as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::ProductID as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::NodeLabel as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::Location as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::HardwareVersion as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::HardwareVersionString as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::SoftwareVersion as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::SoftwareVersionString as _,
            quality: (),
            access: (),
        },
        Attribute {
            id: Attributes::CapabilityMinima as _,
            quality: (),
            access: (),
        },
    ],
};

#[derive(FromPrimitive)]
#[repr(u16)]
enum Attributes {
    DataModelRevision = 0x0000,
    VendorName,
    VendorID,
    ProductName,
    ProductID,
    NodeLabel,
    Location,
    HardwareVersion,
    HardwareVersionString,
    SoftwareVersion,
    SoftwareVersionString,
    // .. left out all the optional attributes for now
    // ManufacturingDate,
    // PartNumber = 0x000c,
    // ProductURL,
    // ProductLabel,
    // SerialNumber,
    // LocalConfigDisabled,
    CapabilityMinima = 0x0013,
}

pub struct BasicInformationCluster<'a> {
    data_version: u32,
    info: DeviceInformation<'a>,
}

#[derive(Clone)]
pub struct DeviceInformation<'a> {
    pub vendor_id: u16,
    pub product_id: u16,
    pub vendor_name: &'a str,
    pub product_name: &'a str,
    pub hardware_version: u16,
    pub software_version: u16,
    pub hardware_version_str: &'a str,
    pub software_version_str: &'a str,
}

impl<'a> BasicInformationCluster<'a> {
    pub fn new(info: DeviceInformation<'a>) -> Self {
        Self {
            data_version: 0,
            info,
        }
    }

    pub fn read(&self, attribute: &AttributePathIB) -> AttributeDataIB {
        if let Some(path) = attribute.attribute {
            // TODO: return error if attribute is unsupported
            let path: Attributes = Attributes::from_u32(path).unwrap();
            let mut encoder = Encoder::default();
            match path {
                Attributes::DataModelRevision => todo!(),
                Attributes::VendorName => todo!(),
                Attributes::VendorID => todo!(),
                Attributes::ProductName => {
                    let value =
                        heapless::Vec::from_slice(self.info.product_name.as_bytes()).unwrap();
                    encoder.write(
                        crate::tlv::TlvType::String(
                            crate::tlv::ElementSize::Byte1,
                            self.info.product_name.len(),
                        ),
                        crate::tlv::TagControl::ContextSpecific(0),
                        crate::tlv::TagLengthValue::String(value),
                    )
                }
                Attributes::ProductID => todo!(),
                Attributes::NodeLabel => todo!(),
                Attributes::Location => todo!(),
                Attributes::HardwareVersion => todo!(),
                Attributes::HardwareVersionString => todo!(),
                Attributes::SoftwareVersion => todo!(),
                Attributes::SoftwareVersionString => todo!(),
                Attributes::CapabilityMinima => todo!(),
            };
            AttributeDataIB {
                data_version: self.data_version,
                path: attribute.clone(),
                data: encoder.inner(),
                interaction_model_revision: 1,
            }
        } else {
            panic!()
        }
    }
}

impl<'a> Handler for BasicInformationCluster<'a> {
    fn handle_read(&self, attr: &AttributePathIB, encoder: &mut AttrDataEncoder) {
        // self.read(attr, encoder.writer)
        panic!()
    }
    fn handle_read2(&self, attr: &AttributePathIB) -> AttributeDataIB {
        self.read(attr)
    }
}
