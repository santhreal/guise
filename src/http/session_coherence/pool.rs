//! Per-host browser profile assignment with bounded session lifetime, keeps a
//! host pinned to one [`HeaderProfile`] for a rotation window so a site sees a
//! stable browser identity rather than one that flickers request-to-request.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

use crate::fingerprint::browser_catalog::HeaderProfile;

/// Per-host browser profile assignment with bounded session lifetime.
pub struct SessionPool {
    profiles: Vec<&'static HeaderProfile>,
    rotate_after_requests: u32,
    bindings: RwLock<HashMap<String, (usize, u32)>>,
    cursor: AtomicUsize,
}

impl SessionPool {
    /// Build a pool over the given browser profiles.
    ///
    /// A zero rotation window is coerced to one so the API stays total.
    ///
    /// # Panics
    ///
    /// Panics if `profiles` is empty.
    #[must_use]
    pub fn new(profiles: Vec<&'static HeaderProfile>, rotate_after_requests: u32) -> Self {
        assert!(
            !profiles.is_empty(),
            "SessionPool::new requires at least one profile"
        );
        Self {
            profiles,
            rotate_after_requests: rotate_after_requests.max(1),
            bindings: RwLock::new(HashMap::new()),
            cursor: AtomicUsize::new(0),
        }
    }

    /// Return the browser profile assigned to `host` for the current window.
    pub fn profile_for(&self, host: &str) -> &'static HeaderProfile {
        debug_assert!(!self.profiles.is_empty());

        let mut bindings = self
            .bindings
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = bindings.get_mut(host) {
            let (idx, count) = *entry;
            if count.saturating_add(1) < self.rotate_after_requests {
                entry.1 += 1;
                return self.profiles[idx];
            }
        }

        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % self.profiles.len();
        bindings.insert(host.to_string(), (idx, 1));
        self.profiles[idx]
    }

    /// Forget every host binding.
    pub fn clear(&self) {
        self.bindings
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    /// Snapshot of `(host, profile_name, request_count)`.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(String, &'static str, u32)> {
        let bindings = self
            .bindings
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        bindings
            .iter()
            .map(|(host, (idx, count))| (host.clone(), self.profiles[*idx].name, *count))
            .collect()
    }
}
