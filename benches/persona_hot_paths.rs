//! Criterion benchmarks for guise hot paths (G255).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use guise::fingerprint::{profile_js, profile_to_overrides, ProfileBundle, StealthProfile};
use guise::http::headers::browser_profile;
use guise::human::keystroke::{plan_keystrokes, TypingPlan};
use guise::pacing::RequestPacer;
use rand::{rngs::StdRng, SeedableRng};

fn profile_js_gen(c: &mut Criterion) {
    let ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    c.bench_function("profile_js/chrome_windows", |b| {
        b.iter(|| profile_js(black_box(&ov)))
    });
}

fn header_build(c: &mut Criterion) {
    c.bench_function("headers/browser_profile/chrome_windows", |b| {
        b.iter(|| browser_profile(black_box(StealthProfile::ChromeWindowsStable)))
    });
}

fn tls_profile(c: &mut Criterion) {
    c.bench_function("bundle/for_browser/chrome_windows", |b| {
        b.iter(|| ProfileBundle::for_browser(black_box(StealthProfile::ChromeWindowsStable)))
    });
}

fn behavioral_sampling(c: &mut Criterion) {
    let plan = TypingPlan::default();
    c.bench_function("keystrokes/plan_hello", |b| {
        b.iter(|| {
            let mut rng = StdRng::seed_from_u64(1);
            plan_keystrokes(black_box("hello"), plan, &mut rng)
        })
    });
}

fn pacing_sample(c: &mut Criterion) {
    let pacer = RequestPacer::page_load();
    c.bench_function("pacer/page_load_next_delay", |b| {
        b.iter(|| {
            let mut rng = StdRng::seed_from_u64(1);
            pacer.next_delay(&mut rng)
        })
    });
}

criterion_group!(
    benches,
    profile_js_gen,
    header_build,
    tls_profile,
    behavioral_sampling,
    pacing_sample
);
criterion_main!(benches);
