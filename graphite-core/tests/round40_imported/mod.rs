//! Round 40 (bootstrap): run an attack file's tests again in the state
//! `graphite evidence import-census` leaves a fresh Core in, under the
//! built-in Gaming profile.
//!
//! Round 39's P0-class findings were reachable only above the confidence
//! floor (`docs/audit/parts/core-decision.md` §2, "Confidence precondition"):
//! a fresh Core sits at 0.44, below every built-in profile, so the Round 38/39
//! harnesses verify under `Custom { 0.40, OfficialManifest }`. After the
//! census import a manifested program's verdict reaches 0.59 under the
//! DEFAULT profiles, so the precondition is met without any custom bar. Each
//! file that includes this module keeps its own tests unchanged and adds a
//! `round40_census_imported::<test>` twin of each (`imported_twins!`) that
//! runs the same body with:
//!
//! - the embedded census imported into the Core under test
//!   (`census_import::import_embedded_into`, the plan and append the CLI
//!   uses, without a trail), and
//! - `WalletProfile::Gaming` — the weakest built-in profile (0.55,
//!   HeuristicInferred) — in place of the file's custom bar.
//!
//! The other built-in profiles require a tier above OfficialManifest
//! (TradingBot SimulationValidated, Treasury CommunityVerified, Enterprise
//! BattleTested), which no import reaches on a fresh Core
//! (`round40_census_import.rs` shows each refuses even the honest controls),
//! so Gaming is the profile the import opens.
//!
//! The switch is thread-local: `#[tokio::test]` runs its body on a
//! current-thread runtime on the test's own thread, so the Core the body
//! builds sees it, and parallel tests do not.

#![allow(dead_code)]

use graphite_core::policy_engine::WalletProfile;
use graphite_core::verification::GraphiteCore;

thread_local! {
    static IMPORTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Cores imported and profiles replaced while the twin ran: a twin
    /// whose body built its Core elsewhere would otherwise pass vacuously.
    static PREPARED: std::cell::Cell<(u32, u32)> = const { std::cell::Cell::new((0, 0)) };
}

/// Whether the running test is the census-imported twin.
pub fn imported() -> bool {
    IMPORTED.with(|c| c.get())
}

/// Run `test` in the imported state.
pub fn with_import(test: fn()) {
    IMPORTED.with(|c| c.set(true));
    PREPARED.with(|c| c.set((0, 0)));
    test();
    IMPORTED.with(|c| c.set(false));
    let (cores, profiles) = PREPARED.with(|c| c.get());
    assert!(
        cores > 0 && profiles > 0,
        "the twin ran without the imported state reaching it ({cores} core(s) imported, {profiles} profile(s) replaced)"
    );
}

/// Import the embedded census into `core` when the twin is running.
pub fn prepare(core: &mut GraphiteCore) {
    if imported() {
        let plan = graphite_core::census_import::import_embedded_into(core)
            .expect("the embedded census imports");
        assert!(
            !plan.imports.is_empty(),
            "the census imported nothing into a fresh core"
        );
        PREPARED.with(|c| c.set((c.get().0 + 1, c.get().1)));
    }
}

/// A fresh Core, census-imported when the twin is running.
pub fn core() -> GraphiteCore {
    let mut core = GraphiteCore::new();
    prepare(&mut core);
    core
}

/// The file's own profile, or Gaming when the twin is running.
pub fn profile(own: WalletProfile) -> WalletProfile {
    if imported() {
        PREPARED.with(|c| c.set((c.get().0, c.get().1 + 1)));
        WalletProfile::Gaming
    } else {
        own
    }
}

/// `round40_census_imported::<name>` for each test named: the same body in
/// the imported state.
#[macro_export]
macro_rules! imported_twins {
    ($($t:ident),* $(,)?) => {
        mod round40_census_imported {
            $(
                #[test]
                fn $t() {
                    super::round40_imported::with_import(super::$t)
                }
            )*
        }
    };
}
