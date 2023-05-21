# Matter Oxide: Another Matter Implementation in Rust

This repository contains yet another Matter implementation in Rust.
The goal of this repository is to cover end devices and controllers, with the main goal of being able to build my own Matter devices.

The project is inspired by, and uses/borrows code from:

* [matter-rs](https://github.com/project-chip/matter-rs), an independent implementation of Matter in Rust (independent in the sense that it does not depend on the C++ megarepo).
* [bare-matter](https://github.com/bjoernQ/bare-matter), TLV implementation, ideas when I got stuck.

## Implementation Status

This section tracks the implementation status of the controller.

From the specification, the below are implemented.

- [ ] Cryptographic Primitives (3)
- [ ] Secure Channel (4)
    - [ ] Discovery (4.3)
    - [ ] _ (4.)
    - [ ] _ (4.)
    - [ ] _ (4.)
    - [ ] _ (4.)
    - [ ] _ (4.)
    - [ ] _ (4.)
    - [ ] _ (4.)
- [ ] Commissioning (5)
- [ ] Device Attestation & Operational Credentials (6)
- [ ] Data Model Specification (7)
- [ ] Interaction Model Specification (8)
- [ ] System Model Specification (9)
- [ ] Interaction Model Encoding Specification (10)
- [ ] Service & Device Management (11)
    - [ ] Basic Information Cluster
    
- [ ] Multiple Fabrics (12)
- [ ] Security Requirements (13)

### Device/Architecture Specific Functionality

For some functionality such as cryptography and networking, we will attempt to use on-device coprocessors where possible.
This section lists the status of such on a few devices.

- Crypto
    - [ ] ESP32-C3, ESP32-C6
    - [ ] nrf52840 Dongle
- BLE
- Thread
- Wifi

### Ideas

Here are some ideas that we can explore to improve the experience of building and using the implementation.

- `serde_tlv` to create a `serde` compatible way of tagging TLV data.
