//! State machines for various interactions

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PASEInitiatorState {
    PBKDFParamRequest,
    Pake1,
    Pake3,
    PakeFinished,
}

pub enum PASeResponderState {
    PBKDFParamResponse,
    Pake2,
    PakeFinished,
}

pub enum CommissioningState {
    X,
}
