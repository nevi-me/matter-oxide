use std::time::SystemTime;

pub fn current_timestamp() -> i64 {
    let now = SystemTime::now();
    // The cast to u64 is safe in our lifetimes
    now.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
