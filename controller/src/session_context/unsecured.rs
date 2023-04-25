//! Unsecured Session Context (4.12.1.1)

use super::SessionRole;

pub struct UnsecuredSessionContext {
    pub session_role: SessionRole,
    pub local_session_id: u16,
    pub peer_session_id: u16,
    pub ephemeral_initiator_node_id: u64,
    // TODO: (4.5.4)
    // It sounds like this state should live outside of the context
    // from 4.5.6 1.c
    pub message_reception_state: (),
    /*
    The downside with storing interaction specific data here is that
    when there's a new interaction, we'd have to alter this context
    to accommodate it. Can we avoid it? What if the interaction and
    session move together but aren't attached to each other?

    Maybe let me implement more interactions and then revisit this
    based on what I learn from them.
    */
}
