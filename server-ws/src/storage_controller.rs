use std::collections::HashMap;

use serde_json::Value;

#[derive(Clone)]
pub struct StorageController {
    storage_path: String,
    data: HashMap<String, Value>,
}

impl StorageController {
    pub async fn new(storage_path: &str) -> Self {
        panic!()
    }

    pub fn file_name(&self) -> &str {
        ""
    }

    pub fn get(&self, key: &str, subkey: Option<&str>) -> Option<Value> {
        None
    }

    pub fn set(&mut self, key: &str, value: Value, subkey: Option<&str>, force: bool) {}

    pub fn remove(&mut self, key: &str, subkey: Option<&str>) {}

    // Does it make sense to store data in-mem and periodically save,
    // or should we just direclty persist to disk? I like the latter.
    // This is where sqlite could work as an alternative storage impl.
}
