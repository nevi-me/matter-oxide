# Matter Controller in Rust

This repository contains a Matter Controller implementation in Rust.
It is inspired by [python-matter-server](https://github.com/home-assistant-libs/python-matter-server/) and aims to be an implementation that is more platform compatible.

The official Matter SDK chip-tool is not built for 32-bit ARM devices, so Home Assistant can't run a Matter server in the affected Raspberry Pis. With the chip shortage (pun?), having a 64-bit Pi is a luxury in the developing world (or if you couldn't afford to get a Pi 4).

The goal of the Rust implementation is to be a drop-in replacement for the Python implementation.
It is built on [matter-rs](https://github.com/project-chip/matter-rs), an independent implementation of Matter in Rust (independent in the sense that it does not depend on the C++ megarepo).

## Implementation Status

This section tracks the implementation status of the controller.

- [ ] Controller
  - [ ] Commissioning a device
- [ ] WebSocket Server
- [ ] WebSocket Client
- [ ] Device Types