#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
// #![cfg_attr(no_std, allow(unused))]
#![allow(unused)]
#![allow(clippy::all)]
#![allow(dead_code)]

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use bytes::BytesMut;
use exchange::ExchangeManager;
use message::{Message, SessionType};
use secure_channel::pake::{PASEManager, Pake2};
use tokio::{
    sync::{
        mpsc::{Receiver, Sender},
        RwLock,
    },
    task::JoinHandle,
};
use transport::udp::UdpInterface;

use crate::{
    crypto::fill_random,
    message::status_report::{GeneralCode, StatusReport},
    session_context::{SecureChannelProtocolOpCode, SecureSessionContext},
};

#[macro_use]
extern crate num_derive;
extern crate alloc;

/// Cluster definitions, servers and clients
pub mod cluster;
pub mod constants;
pub mod controller;
mod crypto;
pub mod data_model;
pub mod end_device;
pub mod exchange;
pub mod experimental;
pub mod fabric;
pub mod interaction_model;
pub mod message;
#[cfg(feature = "controller")]
pub mod root_cert_manager;
pub mod secure_channel;
pub mod session_context;
pub mod tlv;
pub mod transport;
pub mod util;

pub type TlvAnyData = heapless::Vec<u8, 1024>;
