// Attribution: this is from fork::ivmarkov/matter-rs::b::experiments
// It'll eventually get upstreamed, I looked at the code as inspiration
// of how to achieve some data structures in a no_std friendly manner.
// I was struggling with avoiding <dyn Cluster> which would require boxing.

use crate::{
    interaction_model::{transaction::Transaction, AttributeDataIB, AttributePathIB},
    tlv::Encoder,
};

pub struct AttrDataEncoder<'a> {
    pub writer: &'a mut Encoder,
}

pub struct TLVElement {}

// pub struct Transaction {}

pub struct CmdDetails {
    cluster_id: u16,
    endpoint_id: u16,
}

pub struct CmdDataEncoder {}

pub trait ChangeNotifier<T> {
    fn consume_change(&mut self) -> Option<T>;
}

pub trait Handler {
    /// The type of cluster this handler is for. Can be server or client.
    const HANDLER_TYPE: HandlerType = HandlerType::Server;
    fn handle_read(&self, attr: &AttributePathIB, encoder: &mut AttrDataEncoder);
    /// Experimenting with returning attribute data instead of encoding directly
    fn handle_read2(&self, attr: &AttributePathIB) -> AttributeDataIB;

    fn handle_write(&mut self, _attr: &AttributePathIB, _data: &TLVElement) {
        panic!("Attribute not found")
    }

    fn handle_invoke(
        &mut self,
        _transaction: &mut Transaction,
        _cmd: &CmdDetails,
        _data: &TLVElement,
        _encoder: CmdDataEncoder,
    ) {
        panic!("Command not found")
    }

    // Used for client interactions
    fn do_read(&self, attr: &AttributePathIB, encoder: AttrDataEncoder) {
        panic!("do_read should be used by clients")
    }

    fn do_write(&self, attr: &AttributePathIB, encoder: AttrDataEncoder) {
        panic!("do_write should be used by clients")
    }

    fn do_invoke(
        &self,
        _transaction: &mut Transaction,
        _cmd: &CmdDetails,
        _data: &TLVElement,
        _encoder: CmdDataEncoder,
    ) {
        panic!("do_invoke should be used by clients")
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HandlerType {
    Server = 0,
    Client = 1,
}

impl<T> Handler for &mut T
where
    T: Handler,
{
    fn handle_read<'a>(&self, attr: &AttributePathIB, encoder: &mut AttrDataEncoder) {
        (**self).handle_read(attr, encoder)
    }

    fn handle_read2(&self, attr: &AttributePathIB) -> AttributeDataIB {
        panic!("handle_read2 not implemented")
    }

    fn handle_write(&mut self, attr: &AttributePathIB, data: &TLVElement) {
        (**self).handle_write(attr, data)
    }

    fn handle_invoke(
        &mut self,
        transaction: &mut Transaction,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) {
        (**self).handle_invoke(transaction, cmd, data, encoder)
    }
}

pub trait NonBlockingHandler: Handler {}

impl<T> NonBlockingHandler for &mut T where T: NonBlockingHandler {}

pub struct EmptyHandler;

impl EmptyHandler {
    pub const fn chain<H>(
        self,
        handler_endpoint: u16,
        handler_cluster: u16,
        handler: H,
    ) -> ChainedHandler<H, Self> {
        ChainedHandler {
            handler_endpoint,
            handler_cluster,
            handler,
            next: self,
        }
    }
}

impl Handler for EmptyHandler {
    fn handle_read(&self, _attr: &AttributePathIB, encoder: &mut AttrDataEncoder) {
        panic!()
    }

    fn handle_read2(&self, attr: &AttributePathIB) -> AttributeDataIB {
        panic!("handle_read2 not implemented")
    }
}

impl NonBlockingHandler for EmptyHandler {}

impl ChangeNotifier<(u16, u16)> for EmptyHandler {
    fn consume_change(&mut self) -> Option<(u16, u16)> {
        None
    }
}

pub struct ChainedHandler<H, T> {
    pub handler_endpoint: u16,
    pub handler_cluster: u16,
    pub handler: H,
    pub next: T,
}

impl<H, T> ChainedHandler<H, T> {
    pub const fn chain<H2>(
        self,
        handler_endpoint: u16,
        handler_cluster: u16,
        handler: H2,
    ) -> ChainedHandler<H2, Self> {
        ChainedHandler {
            handler_endpoint,
            handler_cluster,
            handler,
            next: self,
        }
    }
}

impl<H, T> Handler for ChainedHandler<H, T>
where
    H: Handler,
    T: Handler,
{
    fn handle_read(&self, attr: &AttributePathIB, encoder: &mut AttrDataEncoder) {
        if Some(self.handler_endpoint) == attr.endpoint
            && Some(self.handler_cluster) == attr.cluster
        {
            self.handler.handle_read(attr, encoder)
        } else {
            self.next.handle_read(attr, encoder)
        }
    }

    fn handle_read2(&self, attr: &AttributePathIB) -> AttributeDataIB {
        dbg!(self.handler_endpoint, self.handler_cluster, &attr);
        // TODO: how do we handle empty endpoints? Wildcards?
        if self.handler_endpoint == attr.endpoint.unwrap_or_default()
            && Some(self.handler_cluster) == attr.cluster
        {
            self.handler.handle_read2(attr)
        } else {
            self.next.handle_read2(attr)
        }
    }

    fn handle_write(&mut self, attr: &AttributePathIB, data: &TLVElement) {
        if Some(self.handler_endpoint) == attr.endpoint
            && Some(self.handler_cluster) == attr.cluster
        {
            self.handler.handle_write(attr, data)
        } else {
            self.next.handle_write(attr, data)
        }
    }

    fn handle_invoke(
        &mut self,
        transaction: &mut Transaction,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) {
        if self.handler_endpoint == cmd.endpoint_id && self.handler_cluster == cmd.cluster_id {
            self.handler.handle_invoke(transaction, cmd, data, encoder)
        } else {
            self.next.handle_invoke(transaction, cmd, data, encoder)
        }
    }
}

impl<H, T> NonBlockingHandler for ChainedHandler<H, T>
where
    H: NonBlockingHandler,
    T: NonBlockingHandler,
{
}

impl<H, T> ChangeNotifier<(u16, u16)> for ChainedHandler<H, T>
where
    H: ChangeNotifier<()>,
    T: ChangeNotifier<(u16, u16)>,
{
    fn consume_change(&mut self) -> Option<(u16, u16)> {
        if self.handler.consume_change().is_some() {
            Some((self.handler_endpoint, self.handler_cluster))
        } else {
            self.next.consume_change()
        }
    }
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! handler_chain_type {
    ($h:ty) => {
        $crate::data_model::handler::ChainedHandler<$h, $crate::data_model::handler::EmptyHandler>
    };
    ($h1:ty, $($rest:ty),+) => {
        $crate::data_model::handler::ChainedHandler<$h1, handler_chain_type!($($rest),+)>
    };
}

/*
The source had an async version, I didn't copy it as I want to work with the sync
version first to understand the implementation.
*/
