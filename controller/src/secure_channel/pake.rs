use crate::{
    constants::*,
    crypto::{fill_random, pbkdf2_hmac, sha256 as crypto_sha256, spake2p::Spake2P},
    message::{status_report::StatusReport, *},
    session_context::{
        SecureChannelProtocolCode, SecureChannelProtocolID, SecureSessionContext, SessionRole,
        UnsecuredSessionContext,
    },
    tlv::*,
};

pub const CRYPTO_PBKDF_ITERATIONS_MIN: u32 = 1000;
pub const CRYPTO_GROUP_SIZE_BYTES: usize = 32;
pub const CRYPTO_PUBLIC_KEY_SIZE_BYTES: usize = CRYPTO_GROUP_SIZE_BYTES * 2 + 1;
pub const CRYPTO_HASH_LEN_BYTES: usize = 32;

pub const CRYPTO_GROUP_SIZE_BITS: usize = CRYPTO_GROUP_SIZE_BYTES * 8;
pub const CRYPTO_W_SIZE_BYTES: usize = CRYPTO_GROUP_SIZE_BYTES + 8;
pub const CRYPTO_W_SIZE_BITS: usize = CRYPTO_W_SIZE_BYTES * 8;

/*
We want to store details about the session context here, or should we store this
in the session context? What else gets stored in the unsecured session context?
*/
pub struct PASEManager {
    spake2p: Option<Spake2P>,
    passcode: u32,
    pbkdf_param_request: heapless::Vec<u8, 512>,
    pbkdf_param_response: heapless::Vec<u8, 512>,
    /// Respondent can set these at the beginning if known or when generated.
    pbkdf_params: Option<PBKDFParams>,
    // This is also stored in the unsecured session context
    // at least as the peer. We can determine this with the
    // session_role there.
    initiator_session_id: u16,
    responder_session_id: u16,
    exchange_id: u16,
    message_counter: u32,
    // Some internal storage
    c_a: [u8; CRYPTO_HASH_LEN_BYTES],
    c_b: [u8; CRYPTO_HASH_LEN_BYTES],
    k_e: [u8; 16],
}

impl PASEManager {
    pub fn initiator(
        passcode: u32,
        session_id: u16,
        exchange_id: u16,
        message_counter: u32,
    ) -> Self {
        Self {
            passcode,
            spake2p: None,
            initiator_session_id: session_id,
            responder_session_id: 0,
            exchange_id,
            message_counter,
            pbkdf_param_request: Default::default(),
            pbkdf_param_response: Default::default(),
            pbkdf_params: None,
            c_a: Default::default(),
            c_b: Default::default(),
            k_e: Default::default(),
        }
    }

    pub fn responder(
        passcode: u32,
        session_id: u16,
        exchange_id: u16,
        message_counter: u32,
        pbkdf_params: Option<PBKDFParams>,
    ) -> Self {
        Self {
            passcode,
            spake2p: None,
            initiator_session_id: 0,
            exchange_id,
            message_counter,
            responder_session_id: session_id,
            pbkdf_param_request: heapless::Vec::new(),
            pbkdf_param_response: heapless::Vec::new(),
            pbkdf_params,
            c_a: Default::default(),
            c_b: Default::default(),
            k_e: Default::default(),
        }
    }

    pub fn pbkdf_param_request(
        &mut self,
        session_context: &mut UnsecuredSessionContext,
    ) -> Message {
        assert_eq!(session_context.session_role, SessionRole::Initiator);
        let mut initiator_random = [0; 32];
        fill_random(&mut initiator_random);
        if session_context.local_session_id == 0 {
            panic!("Can't have a 0 session ID");
        }
        let passcode_id = 0;

        let mut payload_header = ProtocolHeader {
            exchange_id: self.exchange_id,
            ..Default::default()
        };
        // Secure channel by default
        payload_header
            .exchange_flags
            .set(ExchangeFlags::INITIATOR, true);
        payload_header
            .exchange_flags
            .set(ExchangeFlags::RELIABILITY, true);
        payload_header.protocol_opcode = SecureChannelProtocolID::PBKDFParamRequest as _;

        let pbkdf_param_request = PBKDFParamRequest {
            initiator_random,
            initiator_session_id: session_context.local_session_id,
            passcode_id,
            has_pbkdf_params: self.pbkdf_params.is_some(),
            initiator_sed_params: None,
        };
        // Encode the request struct
        let encoded = pbkdf_param_request.to_tlv();
        self.pbkdf_param_request = heapless::Vec::from_slice(encoded.to_slice()).unwrap();
        Message {
            message_header: self.message_header(),
            payload_header: Some(payload_header),
            payload: encoded.inner(),
            integrity_check: None,
        }
    }

    pub fn pbkdf_param_response(
        &mut self,
        session_context: &mut UnsecuredSessionContext,
        request: &PBKDFParamRequest,
    ) -> Message {
        assert_eq!(session_context.session_role, SessionRole::Responder);
        assert_eq!(request.passcode_id, 0);
        let mut responder_random = [0; 32];
        fill_random(&mut responder_random);
        session_context.peer_session_id = request.initiator_session_id;

        let mut pbkdf_params_response = PBKDFParamResponse {
            initiator_random: request.initiator_random,
            responder_random,
            responder_session_id: self.responder_session_id,
            pbkdf_params: None,
            responder_sed_params: None,
        };
        if self.pbkdf_params.is_none() {
            let mut salt = [0; 16];
            fill_random(&mut salt);
            self.pbkdf_params = Some(PBKDFParams {
                iterations: PBKDF_ITERATIONS as _,
                salt: salt.to_vec(),
            });
        }
        if !request.has_pbkdf_params {
            pbkdf_params_response.pbkdf_params = self.pbkdf_params.clone();
        }
        let encoded = pbkdf_params_response.to_tlv();
        self.pbkdf_param_response = heapless::Vec::from_slice(encoded.to_slice()).unwrap();

        // DRY: Payload header
        let mut payload_header = ProtocolHeader::default();
        payload_header.exchange_id = self.exchange_id;
        // Secure channel by default
        payload_header
            .exchange_flags
            .set(ExchangeFlags::INITIATOR, true);
        payload_header
            .exchange_flags
            .set(ExchangeFlags::RELIABILITY, true);
        payload_header.protocol_opcode = SecureChannelProtocolID::PBKDFParamResponse as _;

        Message {
            message_header: self.message_header(),
            payload_header: Some(payload_header),
            payload: encoded.inner(),
            integrity_check: None,
        }
    }

    pub fn pake1(&mut self, session_context: &mut UnsecuredSessionContext) -> Message {
        let request = PBKDFParamResponse::from_tlv(&self.pbkdf_param_response);
        session_context.peer_session_id = request.responder_session_id;

        if self.pbkdf_params.is_none() {
            self.pbkdf_params = request.pbkdf_params.clone();
            // Return an error if responder didn't send params
            assert!(self.pbkdf_params.is_some());
        }
        let PBKDFParams { iterations, salt } = request.pbkdf_params.as_ref().unwrap();
        let s2p = Spake2P::new(self.passcode, *iterations as u16, salt, true);

        let pake1 = Pake1 {
            p_a: s2p.our_key_share().try_into().unwrap(),
        };
        let encoded = pake1.to_tlv();

        self.spake2p = Some(s2p);

        // DRY: Payload header
        let mut payload_header = ProtocolHeader::default();
        payload_header.exchange_id = self.exchange_id;
        // Secure channel by default
        payload_header
            .exchange_flags
            .set(ExchangeFlags::INITIATOR, true);
        payload_header
            .exchange_flags
            .set(ExchangeFlags::RELIABILITY, true);
        payload_header.protocol_opcode = SecureChannelProtocolID::PASEPake1 as _;

        Message {
            message_header: self.message_header(),
            payload_header: Some(payload_header),
            payload: encoded.inner(),
            integrity_check: None,
        }
    }
    pub fn pake2(&mut self, request: &Pake1) -> Message {
        let PBKDFParams { iterations, salt } = self.pbkdf_params.as_ref().unwrap();
        let mut s2p = Spake2P::new(self.passcode, *iterations as _, salt, false);
        s2p.compute_peer_key_share(&request.p_a);

        // Build context
        let mut context = [0; SHA256_HASH_LEN_BYTES];
        let mut hasher = crypto_sha256::Sha256::new();
        hasher.update(&SPAKE2P_CONTEXT_PREFIX);
        hasher.update(&self.pbkdf_param_request);
        hasher.update(&self.pbkdf_param_response);
        hasher.finish(&mut context);

        // Compute (cA, cB, Ke)
        let mut k_e = [0; 16];
        let mut c_a = [0; CRYPTO_HASH_LEN_BYTES];
        let mut c_b = [0; CRYPTO_HASH_LEN_BYTES];
        s2p.compute_key_schedule(&context, &mut k_e, &mut c_a, &mut c_b);

        // dbg!((&k_e, &c_a, &c_b));

        let pake2 = Pake2 {
            p_b: s2p.our_key_share().try_into().unwrap(),
            c_b,
        };
        let encoded = pake2.to_tlv();

        // Store values
        self.spake2p = Some(s2p);
        self.c_a = c_a;
        self.c_b = c_b;
        self.k_e = k_e;

        // DRY: Payload header
        let mut payload_header = ProtocolHeader::default();
        payload_header.exchange_id = self.exchange_id;
        // Secure channel by default
        payload_header
            .exchange_flags
            .set(ExchangeFlags::RELIABILITY, true);
        payload_header.protocol_opcode = SecureChannelProtocolID::PASEPake2 as _;

        Message {
            message_header: self.message_header(),
            payload_header: Some(payload_header),
            payload: encoded.inner(),
            integrity_check: None,
        }
    }
    pub fn pake3(&mut self, request: &Pake2) -> Message {
        // TODO: can provide these to spake2p to avoid repetition
        let mut context = [0; SHA256_HASH_LEN_BYTES];
        let mut hasher = crypto_sha256::Sha256::new();
        hasher.update(&SPAKE2P_CONTEXT_PREFIX);
        hasher.update(&self.pbkdf_param_request);
        hasher.update(&self.pbkdf_param_response);
        hasher.finish(&mut context);

        // Compute (cA, cB, Ke)
        let mut k_e = [0; 16];
        let mut c_a = [0; CRYPTO_HASH_LEN_BYTES];
        let mut c_b = [0; CRYPTO_HASH_LEN_BYTES];
        let s2p = self.spake2p.as_mut().unwrap();
        s2p.compute_peer_key_share(&request.p_b);
        s2p.compute_key_schedule(&context, &mut k_e, &mut c_a, &mut c_b);

        // dbg!((&k_e, &c_a, &c_b));

        // Verify Pake2.cB against cB
        assert_eq!(c_b, request.c_b);

        // DRY: Payload header
        let mut payload_header = ProtocolHeader::default();
        payload_header.exchange_id = self.exchange_id;
        // Secure channel by default
        payload_header
            .exchange_flags
            .set(ExchangeFlags::INITIATOR, true);
        payload_header
            .exchange_flags
            .set(ExchangeFlags::RELIABILITY, true);
        payload_header.protocol_opcode = SecureChannelProtocolID::PASEPake3 as _;

        let pake3 = Pake3 { c_a };
        let encoded = pake3.to_tlv();

        // Store values
        self.c_a = c_a;
        self.c_b = c_b;
        self.k_e = k_e;

        Message {
            message_header: self.message_header(),
            payload_header: Some(payload_header),
            payload: encoded.inner(),
            integrity_check: None,
        }
    }
    pub fn pake_finished(&mut self, pake3: &Pake3) -> Message {
        // Verify Pake3.cA against cA
        assert_eq!(self.c_a, pake3.c_a);
        // Set SessionTimestamp

        // Refer to PakeFinished for more instructions

        // DRY: Payload header
        let mut payload_header = ProtocolHeader::default();
        payload_header.exchange_id = self.exchange_id;
        // Secure channel by default
        payload_header
            .exchange_flags
            .set(ExchangeFlags::RELIABILITY, true);
        payload_header.protocol_opcode = SecureChannelProtocolID::StatusReport as _;
        let status_report = StatusReport {
            general_code: status_report::GeneralCode::Success,
            // TODO: there's a mismatch here, we're going from u16 to u32
            protocol_id: ProtocolID::SecureChannel as u32,
            protocol_code: SecureChannelProtocolCode::SessionEstablishmentSuccess as _,
            protocol_data: vec![],
        };

        // TODO: too many allocations :/
        let mut payload = [0u8; 8];
        status_report.to_payload(&mut payload);
        let payload = heapless::Vec::from_slice(&payload).unwrap();

        Message {
            // TODO: is header different?
            message_header: self.message_header(),
            payload_header: Some(payload_header),
            payload,
            integrity_check: None,
        }
    }
    pub fn set_pbkdf_param_request(&mut self, value: heapless::Vec<u8, 512>) {
        self.pbkdf_param_request = value;
    }

    pub fn set_pbkdf_param_response(&mut self, value: heapless::Vec<u8, 512>) {
        self.pbkdf_param_response = value;
    }
    pub fn get_secrets(&self) -> (&[u8; 16], &[u8; 32], &[u8; 32]) {
        (&self.k_e, &self.c_a, &self.c_b)
    }
    fn message_header(&mut self) -> MessageHeader {
        let mut message_header = MessageHeader::new(0);
        message_header.message_counter = self.message_counter;
        self.message_counter += 1;
        message_header
            .message_flags
            .set(MessageFlags::SOURCE_NODE_ID_PRESENT, true);
        // TODO: ephemeral node ID?
        message_header.source_node_id = Some(1000);
        // TODO: use a builder that validates the rules
        message_header
            .security_flags
            .set(SecurityFlags::SESSION_UNICAST, true);
        // Message flags are set to 0, no need to do that

        message_header
    }
}

/*
Each interaction above returns a message, which is sent to the peer.
I would like to separate the generation of messages from its transmission
so that if necessary peers can send messages out of band to each other.

In each of the above interactions, I'll mutate state, then return a response.
So let's start by returning a message or an error.
 */

#[derive(Clone, Debug)]
pub struct PBKDFParams {
    pub iterations: u32,
    pub salt: Vec<u8>, // 16..32 length
}

pub struct PBKDFParamRequest {
    pub initiator_random: [u8; 32],
    pub initiator_session_id: u16,
    pub passcode_id: u16,
    pub has_pbkdf_params: bool,
    pub initiator_sed_params: Option<SedParameters>,
}

impl PBKDFParamRequest {
    pub fn to_tlv(&self) -> Encoder {
        let mut encoder = Encoder::default();
        encoder.write(
            TlvType::Structure,
            TagControl::Anonymous,
            TagLengthValue::Container,
        );
        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, self.initiator_random.len()),
            TagControl::ContextSpecific(1),
            TagLengthValue::ByteString(heapless::Vec::from_slice(&self.initiator_random).unwrap()),
        );
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte2),
            TagControl::ContextSpecific(2),
            TagLengthValue::Unsigned16(self.initiator_session_id),
        );
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte2),
            TagControl::ContextSpecific(3),
            TagLengthValue::Unsigned16(self.passcode_id),
        );
        encoder.write(
            TlvType::Boolean(self.has_pbkdf_params),
            TagControl::ContextSpecific(4),
            TagLengthValue::Boolean(self.has_pbkdf_params),
        );
        // TODO: sleepy vafiables
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            TagLengthValue::Container,
        );

        encoder
    }

    pub fn from_tlv(data: &[u8]) -> Self {
        let tlv = decode(data);
        let mut initiator_random = None;
        let mut initiator_session_id = None;
        let mut passcode_id = None;
        let mut has_pbkdf_params = None;
        let mut initiator_sed_params: Option<SedParameters> = None;

        let mut element = tlv;
        // Track when we are inside structs
        let mut in_sed_params = false;

        loop {
            match element.get_control() {
                TagControl::Anonymous => {}
                TagControl::ContextSpecific(1) if in_sed_params => {
                    if let TagLengthValue::Unsigned32(value) = element.get_value() {
                        let timeout = Some(value);
                        match initiator_sed_params.as_mut() {
                            Some(params) => {
                                params.sleepy_idle_interval = timeout;
                            }
                            None => {
                                initiator_sed_params = Some(SedParameters {
                                    sleepy_idle_interval: timeout,
                                    sleepy_active_interval: None,
                                })
                            }
                        }
                    }
                }
                TagControl::ContextSpecific(2) if in_sed_params => {
                    if let TagLengthValue::Unsigned32(value) = element.get_value() {
                        let timeout = Some(value);
                        match initiator_sed_params.as_mut() {
                            Some(params) => {
                                params.sleepy_active_interval = timeout;
                            }
                            None => {
                                initiator_sed_params = Some(SedParameters {
                                    sleepy_idle_interval: None,
                                    sleepy_active_interval: timeout,
                                })
                            }
                        }
                    }
                }
                TagControl::ContextSpecific(1) => {
                    if let TagLengthValue::ByteString(bytes) = element.get_value() {
                        initiator_random = Some(bytes.as_slice().try_into().unwrap());
                    }
                }
                TagControl::ContextSpecific(2) => {
                    if let TagLengthValue::Unsigned16(value) = element.get_value() {
                        initiator_session_id = Some(value);
                    }
                }
                TagControl::ContextSpecific(3) => {
                    match element.get_value() {
                        TagLengthValue::Unsigned8(value) => {
                            passcode_id = Some(value as _)
                        }
                        TagLengthValue::Unsigned16(value) => {
                            passcode_id = Some(value as _)
                        }
                        _ => {
                            panic!("Unexpected type for passcode_id")
                        }
                    }
                }
                TagControl::ContextSpecific(4) => {
                    if let TagLengthValue::Boolean(value) = element.get_value() {
                        has_pbkdf_params = Some(value);
                    }
                }
                TagControl::ContextSpecific(5) => {
                    in_sed_params = true;
                }
                other => {
                    panic!("Unexpected tag {other:?}");
                }
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }

        Self {
            initiator_random: initiator_random.unwrap(),
            initiator_session_id: initiator_session_id.unwrap(),
            passcode_id: passcode_id.unwrap_or_default(), // TODO: fix
            has_pbkdf_params: has_pbkdf_params.unwrap(),
            initiator_sed_params,
        }
    }
}

#[derive(Debug)]
pub struct PBKDFParamResponse {
    pub initiator_random: [u8; 32],
    pub responder_random: [u8; 32],
    pub responder_session_id: u16,
    pub pbkdf_params: Option<PBKDFParams>,
    pub responder_sed_params: Option<SedParameters>,
}

impl PBKDFParamResponse {
    pub fn to_tlv(&self) -> Encoder {
        let mut encoder = Encoder::default();
        encoder.write(
            TlvType::Structure,
            TagControl::Anonymous,
            TagLengthValue::Container,
        );
        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, self.initiator_random.len()),
            TagControl::ContextSpecific(1),
            TagLengthValue::ByteString(heapless::Vec::from_slice(&self.initiator_random).unwrap()),
        );
        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, self.responder_random.len()),
            TagControl::ContextSpecific(2),
            TagLengthValue::ByteString(heapless::Vec::from_slice(&self.responder_random).unwrap()),
        );
        encoder.write(
            TlvType::UnsignedInt(ElementSize::Byte2),
            TagControl::ContextSpecific(3),
            TagLengthValue::Unsigned16(self.responder_session_id),
        );
        if let Some(params) = &self.pbkdf_params {
            encoder.write(
                TlvType::Structure,
                TagControl::ContextSpecific(4),
                TagLengthValue::Container,
            );
            encoder.write(
                TlvType::UnsignedInt(ElementSize::Byte4),
                TagControl::ContextSpecific(1),
                TagLengthValue::Unsigned32(params.iterations),
            );
            encoder.write(
                TlvType::ByteString(ElementSize::Byte1, params.salt.len()),
                TagControl::ContextSpecific(2),
                TagLengthValue::ByteString(heapless::Vec::from_slice(&params.salt).unwrap()),
            );
            encoder.write(
                TlvType::EndOfContainer,
                TagControl::ContextSpecific(4),
                TagLengthValue::EndOfContainer,
            );
        }
        // TODO: sleepy vafiables
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            TagLengthValue::Container,
        );
        encoder
    }
    pub fn from_tlv(data: &[u8]) -> Self {
        let tlv = decode(data);
        let mut initiator_random = None;
        let mut responder_random = None;
        let mut responder_session_id = None;
        let mut pbkdf_params: Option<PBKDFParams> = None;
        let mut responder_sed_params: Option<SedParameters> = None;

        let mut element = tlv;
        let mut in_pbkdf_params = false;
        let mut in_sed_params = false;

        loop {
            match element.get_control() {
                TagControl::Anonymous => {}
                TagControl::ContextSpecific(1) if in_pbkdf_params => {
                    let value = if let TagLengthValue::Unsigned32(value) = element.get_value() {
                        value
                    } else if let TagLengthValue::Unsigned16(value) = element.get_value() {
                        value as u32
                    } else {
                        panic!();
                    };
                    match pbkdf_params.as_mut() {
                        Some(params) => {
                            params.iterations = value;
                        }
                        None => {
                            pbkdf_params = Some(PBKDFParams {
                                iterations: value,
                                // TODO: avoid this alloc
                                salt: vec![],
                            })
                        }
                    }
                }
                TagControl::ContextSpecific(2) if in_pbkdf_params => {
                    if let TagLengthValue::ByteString(bytes) = element.get_value() {
                        match pbkdf_params.as_mut() {
                            Some(params) => {
                                params.salt = bytes.to_vec();
                            }
                            None => {
                                pbkdf_params = Some(PBKDFParams {
                                    iterations: 0,
                                    salt: bytes.to_vec(),
                                })
                            }
                        }
                    }
                }
                TagControl::ContextSpecific(1) if in_sed_params => {
                    if let TagLengthValue::Unsigned32(value) = element.get_value() {
                        let timeout = Some(value);
                        match responder_sed_params.as_mut() {
                            Some(params) => {
                                params.sleepy_idle_interval = timeout;
                            }
                            None => {
                                responder_sed_params = Some(SedParameters {
                                    sleepy_idle_interval: timeout,
                                    sleepy_active_interval: None,
                                })
                            }
                        }
                    }
                }
                TagControl::ContextSpecific(2) if in_sed_params => {
                    if let TagLengthValue::Unsigned32(value) = element.get_value() {
                        let timeout = Some(value);
                        match responder_sed_params.as_mut() {
                            Some(params) => {
                                params.sleepy_active_interval = timeout;
                            }
                            None => {
                                responder_sed_params = Some(SedParameters {
                                    sleepy_idle_interval: None,
                                    sleepy_active_interval: timeout,
                                })
                            }
                        }
                    }
                }
                TagControl::ContextSpecific(1) => {
                    if let TagLengthValue::ByteString(bytes) = element.get_value() {
                        initiator_random = Some(bytes.as_slice().try_into().unwrap());
                    }
                }
                TagControl::ContextSpecific(2) => {
                    if let TagLengthValue::ByteString(bytes) = element.get_value() {
                        responder_random = Some(bytes.as_slice().try_into().unwrap());
                    }
                }
                TagControl::ContextSpecific(3) => {
                    if let TagLengthValue::Unsigned16(value) = element.get_value() {
                        responder_session_id = Some(value);
                    }
                }
                TagControl::ContextSpecific(4) => {
                    in_pbkdf_params = true;
                }
                TagControl::ContextSpecific(5) => {
                    in_sed_params = true;
                }

                other => {
                    panic!("Unexpected tag {other:?}");
                }
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }

        Self {
            initiator_random: initiator_random.unwrap(),
            responder_random: responder_random.unwrap(),
            responder_session_id: responder_session_id.unwrap_or_default(),
            pbkdf_params,
            responder_sed_params,
        }
    }
}

#[derive(Debug)]
pub struct SedParameters {
    pub sleepy_idle_interval: Option<u32>,
    pub sleepy_active_interval: Option<u32>,
}

pub struct Pake1 {
    pub p_a: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
}

impl Pake1 {
    pub fn to_tlv(&self) -> Encoder {
        let mut encoder = Encoder::default();

        encoder.write(
            TlvType::Structure,
            TagControl::Anonymous,
            TagLengthValue::Container,
        );
        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, CRYPTO_PUBLIC_KEY_SIZE_BYTES),
            TagControl::ContextSpecific(1),
            TagLengthValue::ByteString(heapless::Vec::from_slice(&self.p_a).unwrap()),
        );
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            TagLengthValue::Container,
        );

        encoder
    }

    pub fn from_tlv(data: &[u8]) -> Self {
        let tlv = decode(data);
        let mut p_a = None;

        let mut element = tlv;

        loop {
            match element.get_control() {
                TagControl::Anonymous => {}
                TagControl::ContextSpecific(1) => {
                    if let TagLengthValue::ByteString(bytes) = element.get_value() {
                        p_a = Some(bytes.as_slice().try_into().unwrap());
                    }
                }
                other => {
                    panic!("Unexpected tag {other:?}");
                }
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }

        Self { p_a: p_a.unwrap() }
    }
}

pub struct Pake2 {
    pub p_b: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pub c_b: [u8; CRYPTO_HASH_LEN_BYTES],
}

impl Pake2 {
    pub fn to_tlv(&self) -> Encoder {
        let mut encoder = Encoder::default();

        encoder.write(
            TlvType::Structure,
            TagControl::Anonymous,
            TagLengthValue::Container,
        );
        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, CRYPTO_PUBLIC_KEY_SIZE_BYTES),
            TagControl::ContextSpecific(1),
            TagLengthValue::ByteString(heapless::Vec::from_slice(&self.p_b).unwrap()),
        );
        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, CRYPTO_HASH_LEN_BYTES),
            TagControl::ContextSpecific(2),
            TagLengthValue::ByteString(heapless::Vec::from_slice(&self.c_b).unwrap()),
        );
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            TagLengthValue::Container,
        );

        encoder
    }

    pub fn from_tlv(data: &[u8]) -> Self {
        let tlv = decode(data);
        let mut p_b = None;
        let mut c_b = None;

        let mut element = tlv;

        loop {
            match element.get_control() {
                TagControl::Anonymous => {}
                TagControl::ContextSpecific(1) => {
                    if let TagLengthValue::ByteString(bytes) = element.get_value() {
                        p_b = Some(bytes.as_slice().try_into().unwrap());
                    }
                }
                TagControl::ContextSpecific(2) => {
                    if let TagLengthValue::ByteString(bytes) = element.get_value() {
                        c_b = Some(bytes.as_slice().try_into().unwrap());
                    }
                }
                other => {
                    panic!("Unexpected tag {other:?}");
                }
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }

        Self {
            p_b: p_b.unwrap(),
            c_b: c_b.unwrap(),
        }
    }
}

pub struct Pake3 {
    pub c_a: [u8; CRYPTO_HASH_LEN_BYTES],
}

impl Pake3 {
    pub fn to_tlv(&self) -> Encoder {
        let mut encoder = Encoder::default();

        encoder.write(
            TlvType::Structure,
            TagControl::Anonymous,
            TagLengthValue::Container,
        );
        encoder.write(
            TlvType::ByteString(ElementSize::Byte1, CRYPTO_HASH_LEN_BYTES),
            TagControl::ContextSpecific(1),
            TagLengthValue::ByteString(heapless::Vec::from_slice(&self.c_a).unwrap()),
        );
        encoder.write(
            TlvType::EndOfContainer,
            TagControl::Anonymous,
            TagLengthValue::Container,
        );

        encoder
    }

    pub fn from_tlv(data: &[u8]) -> Self {
        let tlv = decode(data);
        let mut c_a = None;

        let mut element = tlv;

        loop {
            match element.get_control() {
                TagControl::Anonymous => {}
                TagControl::ContextSpecific(1) => {
                    if let TagLengthValue::ByteString(bytes) = element.get_value() {
                        c_a = Some(bytes.as_slice().try_into().unwrap());
                    }
                }
                other => {
                    panic!("Unexpected tag {other:?}");
                }
            }

            if element.is_last() {
                break;
            }
            element = element.next_in_container();
        }

        Self { c_a: c_a.unwrap() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "fails, using it to investigate TLV differences in implementation"]
    fn decode_tlv_pbkdf_param_response() {
        let data = hex_literal::hex!("15300120c3bf6a81dda5b85c626a582fdaf855cb7085ee308c8976954544afe814cca1a3300220cbcf9f1deebd2e12bac9ae12ef8573f6dfa8a80ef27a0de5529661652ddf315b24030135042501d00730022054dbdb1db37e40d5d57c9e1a84ffde9311a98a843cec2e75b526fa4f424def761818");
        let response = PBKDFParamResponse::from_tlv(&data);
        assert_eq!(response.pbkdf_params.as_ref().unwrap().iterations, 2000);
        let out = response.to_tlv();
        let out = out.to_slice();
        assert_eq!(hex::encode(data), hex::encode(out));
    }
}
