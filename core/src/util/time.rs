#[cfg(not(feature = "end_device"))]
pub fn current_timestamp() -> i64 {
    use std::time::SystemTime;
    let now = SystemTime::now();
    // The cast to u64 is safe in our lifetimes
    now.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[cfg(feature = "end_device")]
pub fn current_timestamp() -> i64 {
    unimplemented!("A clock source is not yet implemented")
}
