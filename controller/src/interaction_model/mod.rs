pub mod path;
pub mod transaction;

// TODO: Augmented Backus-Naur Format
pub struct CommandRequest {
    pub command_path: (),
}