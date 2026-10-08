# Public Rust Lifecycle Showcase

This directory contains a **small, non-production Rust example** so the public showcase accurately reflects that GHOST is a Rust-based system without publishing the private production implementation.

It demonstrates only safe, high-level concepts:

- Tokio-based asynchronous orchestration;
- a three-node message-lifecycle model;
- public algorithm labels for **ML-DSA**, **ML-KEM**, **AES-256-GCM**, and **Shamir Secret Sharing**;
- fragmentation / transfer / verification / reassembly lifecycle stages;
- disruption and recovery as a simulated public flow.

It intentionally does **not** contain production cryptography, key material, protocol internals, routing logic, deployment configuration, or source copied from the private implementation.

The algorithm names in this example describe the public GHOST technology combination. They are not substitute implementations of those algorithms.
