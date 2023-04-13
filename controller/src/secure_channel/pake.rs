use crate::{
    constants::*,
    crypto::{fill_random, pbkdf2_hmac, sha256 as crypto_sha256, spake2p::Spake2P},
    message::*,
    session_context::{
        SecureChannelProtocolID, SecureSessionContext, SessionRole, UnsecuredSessionContext,
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
pub struct PAKEInteraction {
    spake2p: Spake2P,
    pbkdf_param_request: Option<PBKDFParamRequest>,
    pbkdf_param_response: Option<PBKDFParamResponse>,
    /// Respondent can set these at the beginning if known or when generated.
    pbkdf_params: Option<PBKDFParams>,
    // This is also stored in the unsecured session context
    // at least as the peer. We can determine this with the
    // session_role there.
    initiator_session_id: u16,
    responder_session_id: u16,
    // Some internal storage
    c_a: [u8; CRYPTO_HASH_LEN_BYTES],
}

impl PAKEInteraction {
    // The session ID should be generated externally as we need to check for conflicts
    pub fn initiator(session_id: u16) -> Self {
        Self {
            spake2p: Spake2P::new(),
            initiator_session_id: session_id,
            responder_session_id: 0,
            pbkdf_param_request: None,
            pbkdf_param_response: None,
            pbkdf_params: None,
            c_a: Default::default(),
        }
    }

    pub fn responder(session_id: u16, pbkdf_params: Option<PBKDFParams>) -> Self {
        Self {
            spake2p: Spake2P::new(),
            initiator_session_id: 0,
            responder_session_id: session_id,
            pbkdf_param_request: None,
            pbkdf_param_response: None,
            pbkdf_params,
            c_a: Default::default(),
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

        // let mut message_header = MessageHeader::new(0);
        // message_header
        //     .message_flags
        //     .set(MessageFlags::SOURCE_NODE_ID_PRESENT, true);
        // message_header.source_node_id = Some(1000);
        // // TODO: use a builder that validates the rules
        // message_header
        //     .security_flags
        //     .set(SecurityFlags::SESSION_UNICAST, true);
        // // Message flags are set to 0, no need to do that

        let mut payload_header = ProtocolHeader::default();
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
        self.pbkdf_param_request = Some(pbkdf_param_request);
        Message {
            message_header: self.message_header(),
            payload_header: Some(payload_header),
            payload: encoded.to_slice().to_vec(),
            integrity_check: None,
        }
    }

    pub fn pbkdf_param_response(
        &mut self,
        session_context: &mut SecureSessionContext,
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
        self.pbkdf_param_response = Some(pbkdf_params_response);

        Message {
            message_header: self.message_header(),
            payload_header: None,
            payload: encoded.to_slice().to_vec(),
            integrity_check: None,
        }
    }
    pub fn pake1(
        &mut self,
        session_context: &mut UnsecuredSessionContext,
        request: &PBKDFParamResponse,
    ) -> Message {
        session_context.peer_session_id = request.responder_session_id;
        // Generate Crypto_PAKEValues_Initiator
        let mut w0w1 = [0; 2 * CRYPTO_W_SIZE_BYTES];
        // TODO: passcode hardcoded for now
        if self.pbkdf_params.is_none() {
            self.pbkdf_params = request.pbkdf_params.clone();
            // Return an error if responder didn't send params
            assert!(self.pbkdf_params.is_some());
        }
        let PBKDFParams { iterations, salt } = request.pbkdf_params.as_ref().unwrap();
        pbkdf2_hmac(&123456u32.to_le_bytes(), *iterations as _, salt, &mut w0w1);
        let (w0s, w1s) = w0w1.split_at(CRYPTO_W_SIZE_BYTES);
        self.spake2p.set_w0_from_w0s(w0s);
        self.spake2p.set_w1_from_w1s(w1s);
        self.spake2p.set_l_from_w1s(w1s);
        // Generate pA
        let mut p_a = [0; CRYPTO_PUBLIC_KEY_SIZE_BYTES];
        self.spake2p.compute_x(&mut p_a);

        let pake1 = Pake1 { p_a };
        let encoded = pake1.to_tlv();

        Message {
            message_header: self.message_header(),
            payload_header: None,
            payload: encoded.to_slice().to_vec(),
            integrity_check: None,
        }
    }
    pub fn pake2(&mut self, request: &Pake1) -> Message {
        // Generate Crypto_PAKEValues_Initiator
        let mut w0w1 = [0; 2 * CRYPTO_W_SIZE_BYTES];
        // TODO: salt would have been stored in the context
        let salt = [0; 32];
        pbkdf2_hmac(&123456u32.to_le_bytes(), PBKDF_ITERATIONS, &salt, &mut w0w1);
        let (w0s, w1s) = w0w1.split_at(CRYPTO_W_SIZE_BYTES);
        self.spake2p.set_w0_from_w0s(w0s);
        self.spake2p.set_w1_from_w1s(w1s);
        self.spake2p.set_l_from_w1s(w1s);
        // Compute pB
        let mut p_b = [0; CRYPTO_PUBLIC_KEY_SIZE_BYTES];
        self.spake2p.compute_y(&mut p_b);
        // TODO: DRY
        let mut hash = [0; SHA256_HASH_LEN_BYTES];
        let mut context = crypto_sha256::Sha256::new();
        context.update(&SPAKE2P_CONTEXT_PREFIX);
        // TODO: maybe store bytes so we don't do this twice
        context.update(
            self.pbkdf_param_request
                .as_ref()
                .unwrap()
                .to_tlv()
                .to_slice(),
        );
        context.update(
            self.pbkdf_param_response
                .as_ref()
                .unwrap()
                .to_tlv()
                .to_slice(),
        );
        context.finish(&mut hash);
        // Compute (cA, cB, Ke)
        let mut k_e = [0; 16];
        let mut c_b = [0; CRYPTO_HASH_LEN_BYTES];
        self.spake2p
            .compute_p2(&hash, &request.p_a, &p_b, &mut k_e, &mut self.c_a, &mut c_b);

        let pake2 = Pake2 { p_b, c_b };
        let encoded = pake2.to_tlv();

        Message {
            message_header: self.message_header(),
            payload_header: None,
            payload: encoded.to_slice().to_vec(),
            integrity_check: None,
        }
    }
    pub fn pake3(&mut self, request: &Pake2) -> Message {
        // TODO: DRY
        let mut hash = [0; SHA256_HASH_LEN_BYTES];
        let mut context = crypto_sha256::Sha256::new();
        context.update(&SPAKE2P_CONTEXT_PREFIX);
        // TODO: maybe store bytes so we don't do this twice
        context.update(
            self.pbkdf_param_request
                .as_ref()
                .unwrap()
                .to_tlv()
                .to_slice(),
        );
        context.update(
            self.pbkdf_param_response
                .as_ref()
                .unwrap()
                .to_tlv()
                .to_slice(),
        );
        context.finish(&mut hash);
        // Compute (cA, cB, Ke)
        let mut k_e = [0; 16];
        let mut c_a = [0; CRYPTO_HASH_LEN_BYTES];
        let mut c_b = [0; CRYPTO_HASH_LEN_BYTES];
        self.spake2p.compute_p2(
            &hash,
            &self.spake2p.get_x(),
            &request.p_b,
            &mut k_e,
            &mut c_a,
            &mut c_b,
        );
        // Verify Pake2.cB against cB
        assert_eq!(c_b, request.c_b);

        Message {
            message_header: self.message_header(),
            payload_header: None,
            payload: vec![],
            integrity_check: None,
        }
    }
    pub fn pake_finished(&mut self, pake3: &Pake3) -> Message {
        // Verify Pake3.cA against cA
        assert_eq!(self.c_a, pake3.c_a);
        // Set SessionTimestamp

        // Refer to PakeFinished for more instructions

        Message {
            // TODO: is header different?
            message_header: self.message_header(),
            payload_header: None,
            payload: vec![],
            integrity_check: None,
        }
    }
    fn message_header(&self) -> MessageHeader {
        let mut message_header = MessageHeader::new(0);
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

#[derive(Clone)]
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
    fn to_tlv(&self) -> Encoder {
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

    fn from_tlv(data: &[u8]) -> Self {
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
                    if let TagLengthValue::Unsigned16(value) = element.get_value() {
                        passcode_id = Some(value);
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
            passcode_id: passcode_id.unwrap(),
            has_pbkdf_params: has_pbkdf_params.unwrap(),
            initiator_sed_params,
        }
    }
}

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
                    if let TagLengthValue::Unsigned32(value) = element.get_value() {
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
            responder_session_id: responder_session_id.unwrap(),
            pbkdf_params,
            responder_sed_params,
        }
    }
}

pub struct SedParameters {
    pub sleepy_idle_interval: Option<u32>,
    pub sleepy_active_interval: Option<u32>,
}

pub struct Pake1 {
    pub p_a: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
}

impl Pake1 {
    fn to_tlv(&self) -> Encoder {
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

    fn from_tlv(data: &[u8]) -> Self {
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
    fn to_tlv(&self) -> Encoder {
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

    fn from_tlv(data: &[u8]) -> Self {
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
