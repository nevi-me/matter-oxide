pub mod case;
pub mod pake;
pub mod unsecured;

pub const MSG_COUNTER_WINDOW_SIZE: usize = 32;
pub const MSG_COUNTER_SYNC_REQ_JITTER: usize = 500;
pub const MSG_COUNTER_SYNC_TIMEOUT: usize = 400;
