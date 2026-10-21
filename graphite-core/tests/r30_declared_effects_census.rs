//! R30 (§4.5): how every shipped instruction's declaration parses, pinned.
//!
//! L4 judges an observed diff against `expected_state_changes`. The census
//! below is what the R30 rule for unreadable declarations was measured on:
//! how many declarations are silent, unreadable, mixed (a readable line beside
//! an unreadable one — judged strictly), and how many unreadable ones state a
//! class that moves no value, so that a signer's loss under them now blocks.
//! A change to the manifests that moves these numbers fails here, so the rule
//! is re-measured rather than silently re-scoped.
use graphite_core::manifest::load_seed_manifests;
use graphite_core::state_diff::{security_class_line, DeclaredEffects};

#[test]
fn every_shipped_declaration_is_classified_as_measured() {
    let reg = load_seed_manifests();
    let (mut total, mut silent, mut unreadable, mut mixed, mut signer_strict) = (0, 0, 0, 0, 0);
    for m in reg.list() {
        for ix in &m.instructions {
            total += 1;
            let mut with_class = ix.expected_state_changes.clone();
            with_class.push(security_class_line(ix.security_class()));
            let e = DeclaredEffects::parse(&with_class);
            if e.is_silent() {
                silent += 1;
            }
            if e.unrecognised {
                unreadable += 1;
                if !e.class_moves_value() {
                    signer_strict += 1;
                }
            }
            let some_line_unread = ix
                .expected_state_changes
                .iter()
                .any(|l| DeclaredEffects::parse(std::slice::from_ref(l)).unrecognised);
            if !e.unrecognised && some_line_unread {
                mixed += 1;
                assert!(e.is_interpretable(), "{}::{}", m.protocol.name, ix.name);
            }
        }
    }
    assert_eq!(
        (total, silent, unreadable, mixed, signer_strict),
        (3541, 0, 382, 38, 227),
        "(instructions, silent, unreadable, mixed, unreadable-and-signer-strict)"
    );
}
