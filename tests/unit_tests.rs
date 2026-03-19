//! Unit Tests
//!
//! Tests for individual modules and components in isolation.
//! These tests do not require any external services or the gateway binary.
//!
//! Categories:
//!   - plugins: Plugin logic (auth, rate limiting, transformers, logging)
//!   - config: Configuration parsing (env, file, TLS, pool, listeners)
//!   - admin: Admin API (JWT auth, read-only mode, API handlers)
//!   - core: Core data structures (consumers, DNS, proxy, router, websocket)
//!
//! Run with: cargo test --test unit_tests

mod unit;
