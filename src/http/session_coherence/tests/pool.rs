use super::*;

#[test]
fn session_pool_returns_same_profile_for_same_host_until_rotation() {
    let pool = SessionPool::new(PROFILES.iter().collect(), 10);
    let first = pool.profile_for("a.com").name;
    for _ in 0..8 {
        assert_eq!(pool.profile_for("a.com").name, first);
    }
    let _ = pool.profile_for("a.com");
    let (_, _, count) = pool
        .snapshot()
        .into_iter()
        .find(|(host, _, _)| host == "a.com")
        .unwrap();
    assert!(count <= 2);
}

#[test]
fn session_pool_assigns_different_hosts_round_robin() {
    let pool = SessionPool::new(PROFILES.iter().collect(), 100);
    let a = pool.profile_for("a.com").name;
    let b = pool.profile_for("b.com").name;
    assert_ne!(a, b);
}

#[test]
fn session_pool_clear_drops_bindings() {
    let pool = SessionPool::new(PROFILES.iter().collect(), 100);
    let _ = pool.profile_for("a.com");
    let _ = pool.profile_for("b.com");
    assert_eq!(pool.snapshot().len(), 2);
    pool.clear();
    assert!(pool.snapshot().is_empty());
}

#[test]
fn session_pool_zero_rotate_coerces_to_one_not_panic() {
    let pool = SessionPool::new(PROFILES.iter().collect(), 0);
    let _ = pool.profile_for("a.com");
    let _ = pool.profile_for("a.com");
}

#[test]
#[should_panic(expected = "requires at least one profile")]
fn session_pool_empty_profiles_panics_explicitly() {
    let _ = SessionPool::new(vec![], 5);
}

#[test]
fn session_pool_under_concurrent_lookups_remains_consistent() {
    let pool = Arc::new(SessionPool::new(PROFILES.iter().collect(), 50));
    let mut handles = Vec::new();
    for i in 0..20 {
        let pool = Arc::clone(&pool);
        handles.push(std::thread::spawn(move || {
            let host = if i % 2 == 0 { "a.com" } else { "b.com" };
            let mut names = HashSet::new();
            for _ in 0..25 {
                names.insert(pool.profile_for(host).name);
            }
            (host, names)
        }));
    }

    let mut a_names = HashSet::new();
    let mut b_names = HashSet::new();
    for handle in handles {
        let (host, names) = handle.join().unwrap();
        if host == "a.com" {
            a_names.extend(names);
        } else {
            b_names.extend(names);
        }
    }
    assert!(a_names.len() <= PROFILES.len());
    assert!(b_names.len() <= PROFILES.len());
}

#[test]
fn session_pool_rotate_one_does_rotate_each_call() {
    let pool = SessionPool::new(PROFILES.iter().collect(), 1);
    let _ = pool.profile_for("a.com");
    let _ = pool.profile_for("a.com");
    let (_, _, count) = pool
        .snapshot()
        .into_iter()
        .find(|(host, _, _)| host == "a.com")
        .unwrap();
    assert!(count <= 2);
}

#[test]
fn session_pool_counter_never_exceeds_rotate_after_requests() {
    let rotate_at = 5;
    let pool = Arc::new(SessionPool::new(PROFILES.iter().collect(), rotate_at));
    let mut handles = Vec::new();
    for _ in 0..40 {
        let pool = Arc::clone(&pool);
        handles.push(std::thread::spawn(move || {
            pool.profile_for("toctou.com");
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    if let Some((_, _, count)) = pool
        .snapshot()
        .iter()
        .find(|(host, _, _)| host == "toctou.com")
    {
        assert!(*count < rotate_at);
    }
}

#[test]
fn session_pool_counter_resets_after_rotation_boundary() {
    let rotate_at = 3;
    let pool = SessionPool::new(PROFILES.iter().collect(), rotate_at);
    let _ = pool.profile_for("boundary.com");
    let _ = pool.profile_for("boundary.com");
    let _ = pool.profile_for("boundary.com");
    let (_, _, count) = pool
        .snapshot()
        .into_iter()
        .find(|(host, _, _)| host == "boundary.com")
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn session_pool_single_host_many_calls_stays_within_rotate_limit() {
    let rotate_at = 4;
    let pool = SessionPool::new(PROFILES.iter().collect(), rotate_at);
    for _ in 0..50 {
        let _ = pool.profile_for("single.com");
        if let Some((_, _, count)) = pool
            .snapshot()
            .iter()
            .find(|(host, _, _)| host == "single.com")
        {
            assert!(*count < rotate_at);
        }
    }
}

#[test]
fn session_pool_snapshot_does_not_lose_bindings_under_contention() {
    let pool = Arc::new(SessionPool::new(PROFILES.iter().collect(), 100));
    let hosts: Vec<String> = (0..100).map(|i| format!("host-{i}.com")).collect();
    let mut handles = Vec::new();
    for host in &hosts {
        let pool = Arc::clone(&pool);
        let host = host.clone();
        handles.push(std::thread::spawn(move || {
            let _ = pool.profile_for(&host);
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }

    let snapshot = pool.snapshot();
    assert_eq!(snapshot.len(), 100);
    let snapshot_hosts: HashSet<String> =
        snapshot.iter().map(|(host, _, _)| host.clone()).collect();
    for host in &hosts {
        assert!(snapshot_hosts.contains(host));
    }
}
