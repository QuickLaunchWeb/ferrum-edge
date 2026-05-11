//! Process-global registry of named [`SummarySchema`] definitions.
//!
//! Populated by the `transaction_log_schema` plugin at construction time;
//! consumed by other logging plugins that reference a schema by name via
//! `schema_ref:`.
//!
//! The inner map is wholly replaced on config reload via [`begin_reload`] +
//! [`commit_reload`] so renamed/removed schemas don't leak.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

use super::SummarySchema;

#[derive(Default)]
struct RegistryState {
    /// Live map consulted by `lookup_named`.
    schemas: HashMap<String, Arc<SummarySchema>>,
    /// Staging area built by `register_named` during reload; promoted on
    /// `commit_reload`.
    staging: Option<HashMap<String, Arc<SummarySchema>>>,
}

fn registry() -> &'static RwLock<RegistryState> {
    static REGISTRY: OnceLock<RwLock<RegistryState>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(RegistryState::default()))
}

// Lock helpers recover from poisoning by extracting the inner guard.
// A panic in a thread holding the registry lock is rare (no fallible work
// happens while held), but if it ever occurs the registry data itself is
// still valid — the bool poison flag is the only thing wrong. Treating
// poison as fatal would brick every future `schema_ref` lookup across the
// process; recovering keeps the gateway serving from cached state.
fn read_lock() -> RwLockReadGuard<'static, RegistryState> {
    registry().read().unwrap_or_else(PoisonError::into_inner)
}

fn write_lock() -> RwLockWriteGuard<'static, RegistryState> {
    registry().write().unwrap_or_else(PoisonError::into_inner)
}

// Process-wide reload-bracket serializer.
//
// Concurrent reload brackets would interleave: thread A's `begin_reload`
// clobbers thread B's just-built staging map, B's `register_named` writes
// into A's empty staging, and whichever commits last drops the other's
// schemas. plugin_cache reloads always run on the same thread in
// production, but parallel integration tests routinely race: any test
// that starts a gateway drives its own reload bracket on its test
// thread, and absent a process-wide lock those brackets clobber each
// other (and any in-flight test that's mid-bracket on another thread).
//
// `begin_reload` enters the bracket; `commit_reload` leaves it. A
// thread-local depth counter makes the pair reentrant on the same
// thread, so tests can `lock_for_tests()` to hold the bracket across
// their own assertions (which read the live map after committing).
fn reload_serializer() -> &'static Mutex<()> {
    static RELOAD: OnceLock<Mutex<()>> = OnceLock::new();
    RELOAD.get_or_init(|| Mutex::new(()))
}

struct BracketKeeper {
    /// Outermost holder's mutex guard. `Some` iff this thread currently
    /// holds the serializer; the inner `MutexGuard` is dropped when the
    /// outermost bracket leaves (depth → 0), releasing the mutex.
    outer_guard: Option<MutexGuard<'static, ()>>,
    /// Nesting depth — incremented by every `enter_bracket()` on this
    /// thread, decremented by every `leave_bracket()`.
    depth: u32,
}

thread_local! {
    static KEEPER: RefCell<BracketKeeper> = const { RefCell::new(BracketKeeper {
        outer_guard: None,
        depth: 0,
    }) };
}

/// Increment the bracket depth on the current thread, acquiring the
/// process-wide serializer if this is the outermost entry.
fn enter_bracket() {
    let need_acquire = KEEPER.with(|k| k.borrow().depth == 0);
    let guard = if need_acquire {
        // Acquire WITHOUT holding the RefCell borrow — `lock()` may block.
        Some(
            reload_serializer()
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    } else {
        None
    };
    KEEPER.with(|k| {
        let mut k = k.borrow_mut();
        if let Some(g) = guard {
            k.outer_guard = Some(g);
        }
        k.depth += 1;
    });
}

/// Decrement the bracket depth on the current thread, releasing the
/// process-wide serializer if this is the outermost exit.
fn leave_bracket() {
    KEEPER.with(|k| {
        let mut k = k.borrow_mut();
        if k.depth > 0 {
            k.depth -= 1;
            if k.depth == 0 {
                k.outer_guard = None;
            }
        }
    });
}

/// Begin building a fresh named-schema map. Called once per config-load
/// pass before any `transaction_log_schema` plugin's `new()` runs.
///
/// Acquires the process-wide reload-bracket lock so two concurrent
/// reloads serialize at the bracket boundary (without serializing reads
/// against `lookup_named`). The lock is released by [`commit_reload`].
/// Reentrant on the same thread — a test can hold the bracket open via
/// [`lock_for_tests`] and still call begin/commit normally within.
///
/// **Threading invariant:** `begin_reload` / `register_named` /
/// `commit_reload` for one reload pass must all run on the same thread.
/// The serializer guard is stored thread-local; cross-thread brackets
/// leak the guard. plugin_cache and tests both satisfy this naturally.
pub fn begin_reload() {
    enter_bracket();
    let mut state = write_lock();
    state.staging = Some(HashMap::new());
}

/// Register a named schema into the in-progress reload staging area.
///
/// When called between [`begin_reload`] and [`commit_reload`] (the normal
/// loader path), writes to the staging map and rejects duplicates.
///
/// When called outside a reload pass (e.g., from admin-API single-plugin
/// validation via `validate_plugin_config`), this is a no-op. Validation
/// just needs `SummarySchema::compile` to succeed; the registry stays
/// untouched and will be re-populated by the next config-reload pass.
pub fn register_named(name: &str, schema: Arc<SummarySchema>) -> Result<(), String> {
    let mut state = write_lock();
    let Some(staging) = state.staging.as_mut() else {
        return Ok(()); // validation-mode no-op
    };
    if staging.contains_key(name) {
        return Err(format!(
            "transaction_log_schema: named schema '{name}' registered more than once"
        ));
    }
    staging.insert(name.to_string(), schema);
    Ok(())
}

/// Promote the staging area to be the live map. Called after all
/// `transaction_log_schema` plugins for this reload pass have constructed
/// AND the rest of the plugin-cache build has succeeded. Decrements the
/// bracket depth (releases the serializer on outermost exit).
pub fn commit_reload() {
    {
        let mut state = write_lock();
        if let Some(staging) = state.staging.take() {
            state.schemas = staging;
        }
    }
    leave_bracket();
}

/// Discard the staging area without promoting it. Called when the rest
/// of the plugin-cache build fails after schemas have been staged, so
/// the process-global live `schemas` map keeps reflecting the last
/// successfully-applied config. Decrements the bracket depth (releases
/// the serializer on outermost exit).
///
/// Always pair `begin_reload` with exactly one of `commit_reload` or
/// `abort_reload` on the same thread.
pub fn abort_reload() {
    {
        let mut state = write_lock();
        state.staging = None;
    }
    leave_bracket();
}

/// Test-only: hold the reload-bracket serializer across an arbitrary
/// section of test code so the registry's `schemas` map doesn't get
/// stomped by a parallel test's gateway-startup reload between the
/// returned guard's creation and its drop. Inner `begin_reload` /
/// `commit_reload` calls on the same thread are reentrant.
///
/// The returned guard releases the serializer on `Drop`. Tests should
/// scope it to cover both their writes (begin/register/commit) and any
/// `lookup_named` assertions that follow the commit.
#[doc(hidden)]
#[allow(dead_code)]
#[must_use = "drop the guard to release the reload-bracket serializer"]
pub fn lock_for_tests() -> ReloadBracketTestGuard {
    enter_bracket();
    ReloadBracketTestGuard { _private: () }
}

/// RAII handle returned by [`lock_for_tests`].
#[doc(hidden)]
pub struct ReloadBracketTestGuard {
    _private: (),
}

impl Drop for ReloadBracketTestGuard {
    fn drop(&mut self) {
        leave_bracket();
    }
}

/// Look up a named schema. Returns `None` if no schema with this name
/// is registered (either never registered, or removed by a reload).
///
/// If the calling thread is itself in the middle of a reload bracket
/// (between [`begin_reload`] and [`commit_reload`] / [`abort_reload`]),
/// the staging area is the authoritative new state — it shadows the
/// live `schemas` map. This lets the second pass of a plugin-cache
/// build resolve `schema_ref` against the not-yet-committed schemas.
/// External threads (admin API, concurrent reads) continue to see the
/// live committed map, so the atomic-swap-at-commit semantic holds for
/// every reader outside the reload.
pub fn lookup_named(name: &str) -> Option<Arc<SummarySchema>> {
    let on_reload_thread = KEEPER.with(|k| k.borrow().depth > 0);
    let state = read_lock();
    if on_reload_thread && let Some(staging) = &state.staging {
        return staging.get(name).cloned();
    }
    state.schemas.get(name).cloned()
}

/// Snapshot of the registered names (for diagnostics / admin endpoints).
#[allow(dead_code)]
pub fn registered_names() -> Vec<String> {
    let state = read_lock();
    let mut names: Vec<String> = state.schemas.keys().cloned().collect();
    names.sort();
    names
}

/// Test-only: forcefully clear both live and staging state.
///
/// Production callers must use `begin_reload` / `register_named` /
/// `commit_reload`. Exposed (not `#[cfg(test)]`) because integration
/// tests in `tests/integration/` are a separate crate and cannot see
/// items gated on the library's `cfg(test)`.
///
/// Does NOT touch the thread-local bracket keeper — tests holding
/// `lock_for_tests()` continue to own the serializer across this call.
#[doc(hidden)]
#[allow(dead_code)]
pub fn reset_for_tests() {
    let mut state = write_lock();
    state.schemas.clear();
    state.staging = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::utils::log_schema::{
        FieldSpec, MetadataPolicy, SummarySchema, SummaryType, TimestampFormat,
    };

    // The registry is process-global; serialize tests via the same
    // reentrant reload-bracket lock that production callers use, so the
    // bracket stays open across the test's writes AND its assertions.
    fn lock() -> ReloadBracketTestGuard {
        lock_for_tests()
    }

    fn empty_schema() -> Arc<SummarySchema> {
        Arc::new(SummarySchema {
            summary_type: SummaryType::Both,
            fields: Vec::<FieldSpec>::new(),
            metadata: MetadataPolicy::Nested,
            timestamp_format: TimestampFormat::Rfc3339,
        })
    }

    #[test]
    fn register_without_begin_is_validation_noop() {
        let _g = lock();
        reset_for_tests();
        // No begin_reload — should succeed silently without registering.
        assert!(register_named("x", empty_schema()).is_ok());
        assert!(lookup_named("x").is_none());
    }

    #[test]
    fn commit_publishes_staging() {
        let _g = lock();
        reset_for_tests();
        begin_reload();
        register_named("a", empty_schema()).unwrap();
        // The reload thread sees its own staging so plugin construction
        // in the second pass can resolve `schema_ref` before commit.
        assert!(lookup_named("a").is_some());
        // External readers (other threads) still see the live map,
        // which is empty until commit.
        let on_other_thread = std::thread::spawn(lookup_named_a).join().unwrap();
        assert!(
            on_other_thread.is_none(),
            "external readers see only the committed map"
        );
        commit_reload();
        assert!(lookup_named("a").is_some());
        // After commit, external readers see the promoted schemas too.
        let on_other_thread = std::thread::spawn(lookup_named_a).join().unwrap();
        assert!(on_other_thread.is_some());
    }

    fn lookup_named_a() -> Option<Arc<SummarySchema>> {
        lookup_named("a")
    }

    #[test]
    fn abort_discards_staging() {
        let _g = lock();
        reset_for_tests();
        // Seed a live schema so we can confirm it survives the aborted
        // reload.
        begin_reload();
        register_named("keep", empty_schema()).unwrap();
        commit_reload();
        assert!(lookup_named("keep").is_some());

        // Start a reload that registers a new schema, then abort.
        begin_reload();
        register_named("transient", empty_schema()).unwrap();
        abort_reload();

        // The aborted reload's staged schema must NOT leak into the live map.
        assert!(
            lookup_named("transient").is_none(),
            "abort discards staging"
        );
        // The previously-committed schema must survive.
        assert!(
            lookup_named("keep").is_some(),
            "abort preserves last commit"
        );
    }

    #[test]
    fn duplicate_within_reload_rejected() {
        let _g = lock();
        reset_for_tests();
        begin_reload();
        register_named("a", empty_schema()).unwrap();
        let r = register_named("a", empty_schema());
        assert!(r.is_err());
    }

    #[test]
    fn reload_replaces_previous_set() {
        let _g = lock();
        reset_for_tests();
        // First reload: register "a".
        begin_reload();
        register_named("a", empty_schema()).unwrap();
        commit_reload();
        assert!(lookup_named("a").is_some());

        // Second reload: register only "b". "a" should vanish.
        begin_reload();
        register_named("b", empty_schema()).unwrap();
        commit_reload();
        assert!(lookup_named("a").is_none());
        assert!(lookup_named("b").is_some());
    }

    #[test]
    fn registered_names_sorted() {
        let _g = lock();
        reset_for_tests();
        begin_reload();
        register_named("zebra", empty_schema()).unwrap();
        register_named("alpha", empty_schema()).unwrap();
        register_named("mango", empty_schema()).unwrap();
        commit_reload();
        assert_eq!(registered_names(), vec!["alpha", "mango", "zebra"]);
    }
}
