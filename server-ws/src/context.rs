use std::sync::Arc;

use matter::{fabric::FabricMgr, Matter};

#[derive(Clone)]
pub struct MatterContext {
    // A controller doesn't need commissioning, right?
    // If so, this might not be the best abstraction as Matter will start advertising for commissioning.
    // Perhaps a fabric manager would work better
    // matter: Arc<Matter>,
    fabric_manager: Arc<FabricMgr>,
}

impl MatterContext {
    pub fn new() -> Self {
        let fabric_manager = FabricMgr::new().unwrap();
        Self {
            fabric_manager: Arc::new(fabric_manager),
        }
    }
}
