#![allow(dead_code)]

use soroban_sdk::{contracttype, panic_with_error, symbol_short, Address, Env, Symbol};

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum PauseKey {
    /// Single global kill-switch: halts ALL write paths across the contract.
    Global,
    /// Feature-scoped pause: halts only the named write path (e.g. "prescribe").
    Feature(Symbol),
    /// The address authorised to toggle pause flags (admin or multisig proxy).
    PauseAdmin,
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[soroban_sdk::contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PauseError {
    /// The contract (or feature) is currently paused.
    Paused = 200,
    /// Caller is not the pause admin.
    NotPauseAdmin = 201,
    /// Pause admin has not been initialised.
    PauseAdminNotSet = 202,
}

// ── Initialisation ────────────────────────────────────────────────────────────

/// Register the address that may toggle pause flags.
/// Call once during contract `initialize`. Idempotent: a second call with the
/// same admin is a no-op; a different admin overwrites (admin-only).
pub fn init_pause_admin(env: &Env, admin: &Address) {
    env.storage()
        .instance()
        .set(&PauseKey::PauseAdmin, admin);
}

// ── Guards (write paths call these) ──────────────────────────────────────────

/// Panics with `PauseError::Paused` when the global pause flag is set.
/// Read-only paths MUST NOT call this — they bypass it by design.
pub fn require_not_paused(env: &Env) {
    if is_paused(env) {
        panic_with_error!(env, PauseError::Paused);
    }
}

/// Panics with `PauseError::Paused` when either the global flag OR the named
/// feature flag is set.  Read-only paths MUST NOT call this.
pub fn require_not_paused_feature(env: &Env, feature: &Symbol) {
    if is_paused(env) || is_feature_paused(env, feature) {
        panic_with_error!(env, PauseError::Paused);
    }
}

// ── State queries (safe for read paths) ──────────────────────────────────────

pub fn is_paused(env: &Env) -> bool {
    env.storage()
        .instance()
        .get::<PauseKey, bool>(&PauseKey::Global)
        .unwrap_or(false)
}

pub fn is_feature_paused(env: &Env, feature: &Symbol) -> bool {
    env.storage()
        .instance()
        .get::<PauseKey, bool>(&PauseKey::Feature(feature.clone()))
        .unwrap_or(false)
}

// ── Admin toggles ─────────────────────────────────────────────────────────────

/// Pause or unpause the entire contract.
/// `caller` must be the registered pause admin (single admin or multisig proxy).
pub fn set_paused(env: &Env, caller: &Address, paused: bool) {
    caller.require_auth();
    assert_pause_admin(env, caller);
    env.storage()
        .instance()
        .set(&PauseKey::Global, &paused);
    let action = if paused {
        symbol_short!("paused")
    } else {
        symbol_short!("unpaused")
    };
    env.events()
        .publish((symbol_short!("pause"), action), caller.clone());
}

/// Pause or unpause a single named feature write path.
/// `caller` must be the registered pause admin.
pub fn set_feature_paused(env: &Env, caller: &Address, feature: Symbol, paused: bool) {
    caller.require_auth();
    assert_pause_admin(env, caller);
    env.storage()
        .instance()
        .set(&PauseKey::Feature(feature.clone()), &paused);
    let action = if paused {
        symbol_short!("f_paused")
    } else {
        symbol_short!("f_resume")
    };
    env.events()
        .publish((symbol_short!("pause"), action, feature), caller.clone());
}

// ── Internal helper ───────────────────────────────────────────────────────────

fn assert_pause_admin(env: &Env, caller: &Address) {
    let admin: Address = env
        .storage()
        .instance()
        .get(&PauseKey::PauseAdmin)
        .unwrap_or_else(|| panic_with_error!(env, PauseError::PauseAdminNotSet));
    if admin != *caller {
        panic_with_error!(env, PauseError::NotPauseAdmin);
    }
}
