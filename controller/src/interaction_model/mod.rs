use crate::tlv::{decode, ElementSize, Encoder, TagControl, TagLengthValue, Tlv, TlvData, TlvType};

pub mod action;
pub mod path;
pub mod transaction;

pub struct InteractionManager {
    pub transactions: heapless::FnvIndexMap<u8, u8, 16>,
}

// TODO: Augmented Backus-Naur Format
pub struct CommandRequest {
    pub command_path: (),
}

#[repr(u8)]
#[derive(FromPrimitive)]
pub enum InteractionModelProtocolOpCode {
    StatusResponse = 0x01,
    ReadRequest,
    SubscribeRequest,
    SubscribeResponse,
    ReportData,
    WriteRequest,
    WriteResponse,
    InvokeRequest,
    InvokeResponse,
    TimedRequest,
}

pub struct StatusResponseMessage {
    pub status: u32,
}

#[derive(Debug)]
pub struct ReadRequestMessage {
    pub attribute_requests: Option<Vec<AttributePathIB>>,
    pub event_requests: Option<Vec<EventPathIB>>,
    pub event_filters: Option<Vec<EventFilterIB>>,
    pub fabric_filtered: bool,
    pub data_version_filters: Option<Vec<DataVersionFilterIB>>,
    pub interaction_model_revision: u8,
}

impl ReadRequestMessage {
    pub fn to_tlv(&self) {}
    pub fn from_tlv(data: &[u8]) -> Self {
        let tlv = decode(data);

        let mut attribute_requests: Option<Vec<AttributePathIB>> = None;
        let mut in_attribute_requests = false;
        let mut event_requests = None;
        let mut event_filters = None;
        let mut fabric_filtered = false;
        let mut data_version_filters = None;
        let mut interaction_model_revision = 0;

        let mut element = tlv;
        loop {
            println!(
                "Element {:?}, {:?}, {:?}",
                element.get_control(),
                element.get_type(),
                element.get_value()
            );
            match element.get_control() {
                TagControl::Anonymous => match element.get_type() {
                    TlvType::Structure => {
                        // Beginning of struct
                    }
                    TlvType::Array => todo!(),
                    TlvType::List if in_attribute_requests => {
                        println!("Start of attribute requests");
                        element = element.next_in_container();
                        let (ib, e) = AttributePathIB::decode_inner(element);
                        attribute_requests.as_mut().unwrap().push(ib);
                        element = e;
                        continue;
                    }
                    TlvType::EndOfContainer if in_attribute_requests => {
                        in_attribute_requests = false;
                        element = element.next_in_container();
                    }
                    TlvType::EndOfContainer => {
                        // Do nothing?
                    }
                    t => todo!("Unsupported anonymous tag {t:?}"),
                },
                TagControl::ContextSpecific(0) => {
                    // TODO: should also be an array
                    if let TlvType::Array = element.get_type() {
                        in_attribute_requests = true;
                        attribute_requests = Some(vec![]);
                    }
                }
                TagControl::ContextSpecific(1) => {
                    todo!("EventRequests");
                }
                TagControl::ContextSpecific(2) => {
                    todo!("EventFilters");
                }
                TagControl::ContextSpecific(3) => {
                    if let TagLengthValue::Boolean(value) = element.get_value() {
                        fabric_filtered = value;
                    } else {
                        panic!("Invalid value for FabricFiltered");
                    }
                }
                TagControl::ContextSpecific(255) => {
                    if let TagLengthValue::Unsigned8(value) = element.get_value() {
                        interaction_model_revision = value;
                    }
                }
                t => println!(
                    "Encountered tag: {:?} with type: {:?} and value: {:?}",
                    t,
                    element.get_type(),
                    element.get_value()
                ),
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }
        Self {
            attribute_requests,
            event_requests,
            event_filters,
            fabric_filtered,
            data_version_filters,
            interaction_model_revision,
        }
    }
}

pub struct ReportDataMessage {
    pub subscription_id: Option<u32>,
    pub attribute_reports: Option<Vec<AttributeReportIB>>,
    pub event_reports: Option<Vec<EventReportIB>>,
    pub more_chunked_messages: bool,
    pub suppressed_response: bool,
    pub interaction_model_revision: u8,
}

impl ReportDataMessage {
    pub fn to_tlv(&self, encoder: &mut Encoder) {
        encoder.write(
            TlvType::Structure,
            TagControl::Anonymous,
            TagLengthValue::Container,
        );
        if let Some(id) = self.subscription_id {
            encoder.write(
                TlvType::UnsignedInt(ElementSize::Byte4),
                TagControl::ContextSpecific(0),
                TagLengthValue::Unsigned32(id),
            );
        }
        if let Some(reports) = &self.attribute_reports {
            encoder.write(
                TlvType::Array,
                TagControl::ContextSpecific(1),
                TagLengthValue::Container,
            );

            encoder.write(
                TlvType::Structure,
                TagControl::Anonymous,
                TagLengthValue::Container,
            );
            for report in reports {
                report.to_tlv(encoder);
            }
            encoder.write(
                TlvType::EndOfContainer,
                TagControl::Anonymous,
                TagLengthValue::EndOfContainer,
            );

            encoder.write(
                TlvType::EndOfContainer,
                TagControl::Anonymous,
                TagLengthValue::EndOfContainer,
            );
        }
        if let Some(reports) = &self.event_reports {
            todo!("Event reports not yet supported");
        }
        encoder.write(
            TlvType::Boolean(self.more_chunked_messages),
            TagControl::ContextSpecific(3),
            TagLengthValue::Boolean(self.more_chunked_messages),
        );
        encoder.write(
            TlvType::Boolean(self.suppressed_response),
            TagControl::ContextSpecific(4),
            TagLengthValue::Boolean(self.suppressed_response),
        );
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte1),
            TagControl::ContextSpecific(255),
            TagLengthValue::Unsigned8(1),
        );
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            TagLengthValue::EndOfContainer,
        );
    }
    // pub fn from_tlv(data: &[u8]) -> Self {
    //     let tlv = decode(data);

    //     let mut attribute_requests: Option<Vec<AttributePathIB>> = None;
    //     let mut in_attribute_requests = false;
    //     let mut event_requests = None;
    //     let mut event_filters = None;
    //     let mut fabric_filtered = false;
    //     let mut data_version_filters = None;

    //     let mut element = tlv;
    //     loop {
    //         println!(
    //             "Element {:?}, {:?}, {:?}",
    //             element.get_control(),
    //             element.get_type(),
    //             element.get_value()
    //         );
    //         match element.get_control() {
    //             TagControl::Anonymous => match element.get_type() {
    //                 TlvType::Structure => {
    //                     // Beginning of struct
    //                 }
    //                 TlvType::Array => todo!(),
    //                 TlvType::List if in_attribute_requests => {
    //                     element = element.next_in_container();
    //                     let (ib, e) = AttributePathIB::decode_inner(element);
    //                     attribute_requests.as_mut().unwrap().push(ib);
    //                     element = e;
    //                     continue;
    //                 }
    //                 TlvType::EndOfContainer if in_attribute_requests => {
    //                     in_attribute_requests = false;
    //                     element = element.next_in_container();
    //                 }
    //                 TlvType::EndOfContainer => {
    //                     // Do nothing?
    //                 }
    //                 t => todo!("Unsupported anonymous tag {t:?}"),
    //             },
    //             TagControl::ContextSpecific(0) => {
    //                 if let TagLengthValue::Container = element.get_value() {
    //                     in_attribute_requests = true;
    //                     attribute_requests = Some(vec![]);
    //                 }
    //             }
    //             TagControl::ContextSpecific(1) => {
    //                 todo!("EventRequests");
    //             }
    //             TagControl::ContextSpecific(2) => {
    //                 todo!("EventFilters");
    //             }
    //             TagControl::ContextSpecific(3) => {
    //                 if let TagLengthValue::Boolean(value) = element.get_value() {
    //                     fabric_filtered = value;
    //                 } else {
    //                     panic!("Invalid value for FabricFiltered");
    //                 }
    //             }
    //             TagControl::ContextSpecific(255) => {
    //                 println!("Common tag not yet added")
    //             }
    //             t => println!(
    //                 "Encountered tag: {:?} with type: {:?} and value: {:?}",
    //                 t,
    //                 element.get_type(),
    //                 element.get_value()
    //             ),
    //         }

    //         if element.is_last() {
    //             break;
    //         }
    //         element = element.next_in_container();
    //     }
    //     Self {
    //         attribute_requests,
    //         event_requests,
    //         event_filters,
    //         fabric_filtered,
    //         data_version_filters,
    //     }
    // }
}

/// AttributePathIB (10.5.2)
#[derive(Default, Debug, Clone)]
pub struct AttributePathIB {
    pub enable_tag_compression: Option<bool>,
    pub node: Option<u64>,
    pub endpoint: Option<u16>,
    pub cluster: Option<u16>,
    pub attribute: Option<u32>,
    pub list_index: Option<u16>,
}

impl AttributePathIB {
    pub fn to_tlv(&self, encoder: &mut Encoder) {
        if let Some(value) = self.enable_tag_compression {
            encoder.write(
                TlvType::Boolean(value),
                TagControl::ContextSpecific(0),
                TagLengthValue::Boolean(value),
            );
        }
        if let Some(value) = self.node {
            encoder.write(
                TlvType::UnsignedInt(ElementSize::Byte8),
                TagControl::ContextSpecific(1),
                TagLengthValue::Unsigned64(value),
            );
        }
        if let Some(value) = self.endpoint {
            encoder.write(
                TlvType::UnsignedInt(ElementSize::Byte2),
                TagControl::ContextSpecific(2),
                TagLengthValue::Unsigned16(value),
            );
        }
        if let Some(value) = self.cluster {
            encoder.write(
                TlvType::UnsignedInt(ElementSize::Byte2),
                TagControl::ContextSpecific(3),
                TagLengthValue::Unsigned16(value),
            );
        }
        if let Some(value) = self.attribute {
            encoder.write(
                TlvType::UnsignedInt(ElementSize::Byte4),
                TagControl::ContextSpecific(4),
                TagLengthValue::Unsigned32(value),
            );
        }
        if let Some(value) = self.list_index {
            encoder.write(
                TlvType::UnsignedInt(ElementSize::Byte2),
                TagControl::ContextSpecific(5),
                TagLengthValue::Unsigned16(value),
            );
        }
        // -
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte1),
            TagControl::ContextSpecific(255),
            TagLengthValue::Unsigned8(1),
        );
    }
    fn decode_inner(tlv: TlvData) -> (Self, TlvData) {
        let mut ib = Self {
            ..Default::default()
        };
        let mut element = tlv;
        loop {
            println!(
                "AttributePathIB Element {:?}, {:?}, {:?}",
                element.get_control(),
                element.get_type(),
                element.get_value()
            );
            match element.get_control() {
                TagControl::Anonymous if element.get_type() == TlvType::EndOfContainer => {
                    // element = element.next_in_container();
                    break;
                }
                TagControl::ContextSpecific(0) => {
                    if let TagLengthValue::Boolean(value) = element.get_value() {
                        ib.enable_tag_compression = Some(value);
                    } else {
                        panic!("Invalid value")
                    }
                }
                TagControl::ContextSpecific(1) => {
                    if let TagLengthValue::Unsigned64(value) = element.get_value() {
                        ib.node = Some(value);
                    } else {
                        panic!("Invalid value")
                    }
                }
                TagControl::ContextSpecific(2) => {
                    let value = match element.get_value() {
                        TagLengthValue::Unsigned8(value) => value as _,
                        TagLengthValue::Unsigned16(value) => value as _,
                        t => panic!("Invalid value {t:?}"),
                    };
                    ib.endpoint = Some(value);
                }
                TagControl::ContextSpecific(3) => {
                    let value = match element.get_value() {
                        TagLengthValue::Unsigned8(value) => value as _,
                        TagLengthValue::Unsigned16(value) => value as _,
                        TagLengthValue::Unsigned32(value) => value as _,
                        t => panic!("Invalid value {t:?}"),
                    };
                    ib.cluster = Some(value);
                }
                TagControl::ContextSpecific(4) => {
                    let value = match element.get_value() {
                        TagLengthValue::Unsigned8(value) => value as _,
                        TagLengthValue::Unsigned16(value) => value as _,
                        TagLengthValue::Unsigned32(value) => value as _,
                        t => panic!("Invalid value {t:?}"),
                    };
                    ib.attribute = Some(value);
                }
                TagControl::ContextSpecific(5) => {
                    // TODO: this is nullable
                    let value = match element.get_value() {
                        TagLengthValue::Unsigned8(value) => value as _,
                        TagLengthValue::Unsigned16(value) => value as _,
                        t => panic!("Invalid value {t:?}"),
                    };
                    ib.list_index = Some(value);
                }
                t => todo!("{t:?} not covered"),
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }
        (ib, element)
    }
}

#[derive(Debug)]
pub struct DataVersionFilterIB {
    pub path: ClusterPathIB,
    pub data_version: u32,
}

/// 10.5.4
pub struct AttributeDataIB {
    pub data_version: u32,
    pub path: AttributePathIB,
    pub data: heapless::Vec<u8, 1024>, // TODO: what's a good representation?
    pub interaction_model_revision: u8,
}

impl AttributeDataIB {
    pub fn to_tlv(&self, encoder: &mut Encoder) {
        // encoder.write(
        //     TlvType::Structure,
        //     TagControl::ContextSpecific(0),
        //     TagLengthValue::Container,
        // );
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte4),
            TagControl::ContextSpecific(0),
            TagLengthValue::Unsigned32(self.data_version),
        );
        encoder.write(
            TlvType::List,
            TagControl::ContextSpecific(1),
            TagLengthValue::Container,
        );
        self.path.to_tlv(encoder);
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::ContextSpecific(1),
            TagLengthValue::EndOfContainer,
        );

        let data = heapless::Vec::from_slice(self.data.as_slice()).unwrap();
        encoder.write(
            // TODO: optimise length
            TlvType::ByteString(ElementSize::Byte2, self.data.len()),
            TagControl::ContextSpecific(2),
            TagLengthValue::ByteString(data),
        );
        // --
        // encoder.write(
        //     TlvType::UnsignedInt(ElementSize::Byte1),
        //     TagControl::ContextSpecific(255),
        //     TagLengthValue::Unsigned8(1),
        // );
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            TagLengthValue::EndOfContainer,
        );
    }
}

pub struct AttributeReportIB {
    pub attribute_status: AttributeStatusIB,
    pub attribute_data: AttributeDataIB,
}

impl AttributeReportIB {
    pub fn to_tlv(&self, encoder: &mut Encoder) {
        // encoder.write(
        //     TlvType::Structure,
        //     TagControl::Anonymous,
        //     TagLengthValue::Container,
        // );
        encoder.write(
            TlvType::Structure,
            TagControl::ContextSpecific(0),
            TagLengthValue::Container,
        );
        self.attribute_status.to_tlv(encoder);
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            TagLengthValue::EndOfContainer,
        );

        encoder.write(
            TlvType::Structure,
            TagControl::ContextSpecific(1),
            TagLengthValue::Container,
        );
        self.attribute_data.to_tlv(encoder);
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            TagLengthValue::EndOfContainer,
        );

        // ---
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte1),
            TagControl::ContextSpecific(255),
            TagLengthValue::Unsigned8(1),
        );

        // encoder.write(
        //     TlvType::EndOfContainer,
        //     TagControl::Anonymous,
        //     TagLengthValue::EndOfContainer,
        // );
    }
}

#[derive(Debug, Default)]
pub struct EventFilterIB {
    pub node: Option<u64>,
    pub event_min: u64,
}

impl EventFilterIB {
    fn decode_inner(tlv: TlvData) -> (Self, TlvData) {
        let mut ib = Self {
            ..Default::default()
        };
        let mut element = tlv;
        loop {
            println!(
                "EventFilterIB Element {:?}, {:?}, {:?}",
                element.get_control(),
                element.get_type(),
                element.get_value()
            );
            match element.get_control() {
                TagControl::Anonymous if element.get_type() == TlvType::EndOfContainer => {
                    // element = element.next_in_container();
                    break;
                }
                // TagControl::ContextSpecific(0) => {
                //     if let TagLengthValue::Boolean(value) = element.get_value() {
                //         ib.enable_tag_compression = Some(value);
                //     } else {
                //         panic!("Invalid value")
                //     }
                // }
                // TagControl::ContextSpecific(1) => {
                //     if let TagLengthValue::Unsigned64(value) = element.get_value() {
                //         ib.node = Some(value);
                //     } else {
                //         panic!("Invalid value")
                //     }
                // }
                t => todo!("{t:?} not covered"),
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }
        (ib, element)
    }
}

#[derive(Debug)]
pub struct ClusterPathIB {
    pub node: Option<u64>,
    pub endpoint: u16,
    pub cluster: u32,
}
#[derive(Debug)]
pub struct EventPathIB {
    pub node: Option<u64>,
    pub endpoint: u16,
    pub cluster: u32,
    pub event: u32,
    pub is_urgent: bool,
}

#[derive(Debug)]
pub struct EventDataIB {
    pub path: EventPathIB,
    pub event_number: u64,
    pub priority: u8,
    pub timestamp: EventDataIBTimestamp,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum EventDataIBTimestamp {
    EpochTimestamp(i64),
    SystemTimestamp(u64),
    DeltaEpochTimestamp(u64),  // Optional,
    DeltaSystemTimestamp(u64), // Optional
}

pub struct EventReportIB {
    pub event_status: EventStatusIB,
    pub event_data: EventDataIB,
}

pub struct CommandPathIB {
    pub endpoint: u16,
    pub cluster: u32,
    pub command: u32,
}

pub struct InvokeResponseIB {
    pub command: CommandDataIB,
    pub status: CommandStatusIB,
}

pub struct CommandStatusIB {
    pub path: CommandPathIB,
    pub status: StatusIB,
}

pub struct EventStatusIB {
    pub path: EventPathIB,
    pub status: StatusIB,
}

pub struct CommandDataIB {
    pub command_path: CommandPathIB,
    pub command_fields: Vec<u8>,
}

pub struct AttributeStatusIB {
    pub path: AttributePathIB,
    pub status: StatusIB,
}

impl AttributeStatusIB {
    pub fn to_tlv(&self, encoder: &mut Encoder) {
        encoder.write(
            TlvType::List,
            TagControl::ContextSpecific(0),
            TagLengthValue::Container,
        );
        self.path.to_tlv(encoder);
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            TagLengthValue::EndOfContainer,
        );

        encoder.write(
            TlvType::Structure,
            TagControl::ContextSpecific(1),
            TagLengthValue::Container,
        );
        self.status.to_tlv(encoder);
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            TagLengthValue::EndOfContainer,
        );
    }
}

#[derive(Default)]
pub struct StatusIB {
    pub status: u16,
    pub cluster_status: u16,
}

impl StatusIB {
    pub fn to_tlv(&self, encoder: &mut Encoder) {
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte2),
            TagControl::ContextSpecific(0),
            TagLengthValue::Unsigned16(self.status),
        );
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte2),
            TagControl::ContextSpecific(1),
            TagLengthValue::Unsigned16(self.cluster_status),
        );
    }
    fn decode_inner(tlv: TlvData) -> (Self, TlvData) {
        let mut ib = Self {
            ..Default::default()
        };
        let mut element = tlv;
        loop {
            println!(
                "StatusIB Element {:?}, {:?}, {:?}",
                element.get_control(),
                element.get_type(),
                element.get_value()
            );
            match element.get_control() {
                TagControl::Anonymous if element.get_type() == TlvType::EndOfContainer => {
                    // element = element.next_in_container();
                    break;
                }
                TagControl::ContextSpecific(0) => {
                    if let TagLengthValue::Unsigned16(value) = element.get_value() {
                        ib.status = value;
                    } else {
                        panic!("Invalid value for status")
                    }
                }
                TagControl::ContextSpecific(1) => {
                    if let TagLengthValue::Unsigned16(value) = element.get_value() {
                        ib.cluster_status = value;
                    } else {
                        panic!("Invalid value for cluster_status")
                    }
                }
                t => todo!("{t:?} not covered"),
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }
        (ib, element)
    }
}
