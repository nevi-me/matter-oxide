/// Common action information (8.2.5.1)
pub struct ActionInformation {
    pub im_revision: u8,
    pub action: (),
    pub transaction_id: (),
    pub fabric_index: (),
    pub source_node: u64,
    pub dest_node: Option<u64>,
    pub dest_group: Option<u32>,
    // ... action specific
}
