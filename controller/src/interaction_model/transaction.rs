use crate::exchange::Exchange;

pub struct Transaction<'a> {
    state: TransactionState,
    exchange: &'a Exchange,
}

pub enum TransactionState {
    Active,
    Completed,
}
