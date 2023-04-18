// Attribution: this is from fork::ivmarkov/matter-rs::b::experiments
// It'll eventually get upstreamed, I looked at the code as inspiration
// of how to achieve some data structures in a no_std friendly manner.
// I was struggling with avoiding <dyn Cluster> which would require boxing.

// Stubs for now
pub struct AttrDetails {
    cluster_id: u16,
    endpoint_id: u16,
}

pub struct AttrDataEncoder {}

pub struct TLVElement {}

pub struct Transaction {}

pub struct CmdDetails {
    cluster_id: u16,
    endpoint_id: u16,
}

pub struct CmdDataEncoder {}

pub trait ChangeNotifier<T> {
    fn consume_change(&mut self) -> Option<T>;
}

pub trait Handler {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder);

    fn write(&mut self, _attr: &AttrDetails, _data: &TLVElement) {
        panic!("Attribute not found")
    }

    fn invoke(
        &mut self,
        _transaction: &mut Transaction,
        _cmd: &CmdDetails,
        _data: &TLVElement,
        _encoder: CmdDataEncoder,
    ) {
        panic!("Command not found")
    }
}

impl<T> Handler for &mut T
where
    T: Handler,
{
    fn read<'a>(&self, attr: &AttrDetails, encoder: AttrDataEncoder) {
        (**self).read(attr, encoder)
    }

    fn write(&mut self, attr: &AttrDetails, data: &TLVElement) {
        (**self).write(attr, data)
    }

    fn invoke(
        &mut self,
        transaction: &mut Transaction,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) {
        (**self).invoke(transaction, cmd, data, encoder)
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
    fn read(&self, _attr: &AttrDetails, _encoder: AttrDataEncoder) {
        panic!()
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
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) {
        if self.handler_endpoint == attr.endpoint_id && self.handler_cluster == attr.cluster_id {
            self.handler.read(attr, encoder)
        } else {
            self.next.read(attr, encoder)
        }
    }

    fn write(&mut self, attr: &AttrDetails, data: &TLVElement) {
        if self.handler_endpoint == attr.endpoint_id && self.handler_cluster == attr.cluster_id {
            self.handler.write(attr, data)
        } else {
            self.next.write(attr, data)
        }
    }

    fn invoke(
        &mut self,
        transaction: &mut Transaction,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) {
        if self.handler_endpoint == cmd.endpoint_id && self.handler_cluster == cmd.cluster_id {
            self.handler.invoke(transaction, cmd, data, encoder)
        } else {
            self.next.invoke(transaction, cmd, data, encoder)
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
