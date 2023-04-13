pub mod message_counter_sync;
pub mod secure;
/// Unsecured Session Context (4.12.1.1)
pub mod unsecured;

pub use secure::*;
pub use unsecured::*;

pub enum SessionContext {
    MCSP,
    Secure(SecureSessionContext),
    Unsecured(UnsecuredSessionContext),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}
