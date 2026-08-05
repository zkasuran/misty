// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The gate on this crate (SPEC §4): "for any set of concurrent operations, every
//! application order MUST produce byte-identical state."
//!
//! The three laws are asserted **separately**, because they break for different
//! reasons and a test that only reports "these two states differ" does not say
//! which mistake was made:
//!
//! * **commutativity** fails when a rule has a "prefer mine" branch — the classic
//!   is resolving an exact clock tie by keeping `self`;
//! * **associativity** fails when a rule looks at more than the two values in front
//!   of it, such as a fork that draws a fresh id instead of deriving one;
//! * **idempotence** fails when a rule *accumulates* instead of joining — summing a
//!   G-counter on merge rather than taking the per-key maximum.
//!
//! "Byte-identical" is measured on [`ItemSet::fingerprint`], which is the
//! concatenation of the length-prefixed stored CBOR encodings. Comparing encodings
//! rather than Rust values is deliberate: two sets that are `==` but encode
//! differently would still diverge on disk and over the wire, which is where
//! convergence actually has to hold.

mod support;

use misty_crypto::ItemId;
use misty_otp::{Clock, FixedClock, SecretBytes};
use misty_vault::{Edit, ForkIds, ItemSet, MemoryStore, Vault, VaultForkIds};
use proptest::prelude::*;
use support::{new_item, peer, sync, vault_key, NOW};

/// How many independent devices each case runs.
const REPLICAS: usize = 3;

/// One offline edit.
#[derive(Clone, Debug)]
enum Op {
    Nickname {
        item: usize,
        value: u8,
    },
    Note {
        item: usize,
        value: u8,
    },
    Favorite {
        item: usize,
        on: bool,
    },
    Archive {
        item: usize,
        on: bool,
    },
    AddTag {
        item: usize,
        tag: u8,
    },
    RemoveTag {
        item: usize,
        tag: u8,
    },
    AddOrigin {
        item: usize,
        origin: u8,
    },
    RecordUse {
        item: usize,
    },
    AdvanceCounter {
        item: usize,
    },
    Trash {
        item: usize,
    },
    Restore {
        item: usize,
    },
    Delete {
        item: usize,
    },
    RepairSecret {
        item: usize,
        secret: u8,
    },
    /// Move this replica's clock forward, so some edits tie on the millisecond and
    /// some do not.
    Wait {
        ms: u8,
    },
}

fn op_strategy(items: usize) -> impl Strategy<Value = Op> {
    let item = 0..items;
    prop_oneof![
        (item.clone(), any::<u8>()).prop_map(|(item, value)| Op::Nickname { item, value }),
        (item.clone(), any::<u8>()).prop_map(|(item, value)| Op::Note { item, value }),
        (item.clone(), any::<bool>()).prop_map(|(item, on)| Op::Favorite { item, on }),
        (item.clone(), any::<bool>()).prop_map(|(item, on)| Op::Archive { item, on }),
        (item.clone(), 0u8..4).prop_map(|(item, tag)| Op::AddTag { item, tag }),
        (item.clone(), 0u8..4).prop_map(|(item, tag)| Op::RemoveTag { item, tag }),
        (item.clone(), 0u8..3).prop_map(|(item, origin)| Op::AddOrigin { item, origin }),
        item.clone().prop_map(|item| Op::RecordUse { item }),
        item.clone().prop_map(|item| Op::AdvanceCounter { item }),
        item.clone().prop_map(|item| Op::Trash { item }),
        item.clone().prop_map(|item| Op::Restore { item }),
        item.clone().prop_map(|item| Op::Delete { item }),
        (item, 0u8..3).prop_map(|(item, secret)| Op::RepairSecret { item, secret }),
        (0u8..3).prop_map(|ms| Op::Wait { ms }),
    ]
}

type Peer = Vault<MemoryStore, FixedClock>;

/// Applies one op. Every op here is one this crate promises cannot fail on a live
/// item, so a failure is a bug rather than something to tolerate.
fn apply(vault: &mut Peer, ids: &[ItemId], op: &Op) {
    let pick = |index: usize| ids.get(index % ids.len()).copied().expect("an item");
    match *op {
        Op::Nickname { item, value } => vault
            .update(
                &pick(item),
                Edit::new().nickname(Some(format!("nick {value}"))),
            )
            .expect("nickname"),
        Op::Note { item, value } => vault
            .update(&pick(item), Edit::new().note(Some(format!("note {value}"))))
            .expect("note"),
        Op::Favorite { item, on } => vault
            .update(&pick(item), Edit::new().favorite(on))
            .expect("favorite"),
        Op::Archive { item, on } => vault
            .update(&pick(item), Edit::new().archived(on))
            .expect("archive"),
        Op::AddTag { item, tag } => vault
            .add_tag(&pick(item), format!("tag{tag}"))
            .expect("add tag"),
        Op::RemoveTag { item, tag } => vault
            .remove_tag(&pick(item), &format!("tag{tag}"))
            .expect("remove tag"),
        Op::AddOrigin { item, origin } => vault
            .add_origin(&pick(item), &format!("site{origin}.example"))
            .expect("add origin"),
        Op::RecordUse { item } => vault.record_use(&pick(item)).expect("record use"),
        Op::AdvanceCounter { item } => {
            vault.advance_hotp_counter(&pick(item)).expect("advance");
        }
        Op::Trash { item } => vault.trash_item(&pick(item)).expect("trash"),
        Op::Restore { item } => vault.restore_item(&pick(item)).expect("restore"),
        Op::Delete { item } => vault.delete_item(&pick(item)).expect("delete"),
        Op::RepairSecret { item, secret } => vault
            .repair_secret(&pick(item), SecretBytes::from_slice(&[secret + 0x40; 10]))
            .expect("repair"),
        Op::Wait { ms } => {
            let clock = vault.clock();
            clock.set(clock.now_unix_ms() + u64::from(ms));
        }
    }
}

/// Builds `REPLICAS` vaults that all start from the same `items` items, then applies
/// each replica's own op list to it offline.
///
/// The seed phase matters: two devices can only *diverge* on state they both have,
/// and an id is 16 random bytes, so there is no way for two devices to
/// independently invent the same item. Real divergence starts from a shared
/// history, and so does this.
fn diverge(items: usize, per_replica: &[Vec<Op>]) -> (Vec<ItemSet>, Vec<ItemId>) {
    let seeds: Vec<u8> = (0..=u8::try_from(REPLICAS).expect("small")).collect();
    let mut genesis = peer(0, &seeds, NOW);
    let ids: Vec<ItemId> = (0..items)
        .map(|index| {
            genesis
                .add(new_item(
                    &format!("issuer {index}"),
                    &format!("account {index}"),
                    &[0x30 + u8::try_from(index).expect("small"); 10],
                ))
                .expect("add")
        })
        .collect();

    let mut sets = Vec::with_capacity(REPLICAS);
    for (replica, ops) in per_replica.iter().enumerate() {
        let seed = u8::try_from(replica + 1).expect("small");
        let mut vault = peer(seed, &seeds, NOW);
        sync(&genesis, &mut vault);
        for op in ops {
            apply(&mut vault, &ids, op);
        }
        sets.push(vault.item_set().clone());
    }
    (sets, ids)
}

fn fingerprint(set: &ItemSet) -> Vec<u8> {
    set.fingerprint().expect("fingerprint").to_vec()
}

/// `left ⊕ right`.
fn join(left: &ItemSet, right: &ItemSet, fork: &impl ForkIds) -> ItemSet {
    let mut out = left.clone();
    out.merge(right, fork, &mut Vec::new()).expect("merge");
    out
}

/// Folds a list of sets left to right.
fn join_all<'a>(sets: impl IntoIterator<Item = &'a ItemSet>, fork: &impl ForkIds) -> ItemSet {
    let mut out = ItemSet::new();
    for set in sets {
        out = join(&out, set, fork);
    }
    out
}

fn ops_strategy(items: usize) -> impl Strategy<Value = Vec<Vec<Op>>> {
    proptest::collection::vec(
        proptest::collection::vec(op_strategy(items), 0..7),
        REPLICAS..=REPLICAS,
    )
}

proptest! {
    // Each case builds four vaults and seals a real envelope per write, so the
    // case count is chosen to keep the suite inside a few seconds rather than
    // because 256 would be less thorough.
    #![proptest_config(ProptestConfig { cases: 40, ..ProptestConfig::default() })]

    /// `a ⊕ b == b ⊕ a`.
    #[test]
    fn merge_is_commutative(ops in ops_strategy(3)) {
        let key = vault_key();
        let fork = VaultForkIds::new(&key);
        let (sets, _) = diverge(3, &ops);
        for pair in sets.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            prop_assert_eq!(
                fingerprint(&join(a, b, &fork)),
                fingerprint(&join(b, a, &fork)),
                "merge is not commutative"
            );
        }
    }

    /// `(a ⊕ b) ⊕ c == a ⊕ (b ⊕ c)`.
    #[test]
    fn merge_is_associative(ops in ops_strategy(3)) {
        let key = vault_key();
        let fork = VaultForkIds::new(&key);
        let (sets, _) = diverge(3, &ops);
        let (a, b, c) = (&sets[0], &sets[1], &sets[2]);
        let left = join(&join(a, b, &fork), c, &fork);
        let right = join(a, &join(b, c, &fork), &fork);
        prop_assert_eq!(
            fingerprint(&left),
            fingerprint(&right),
            "merge is not associative"
        );
    }

    /// `a ⊕ a == a`, and re-merging a state already absorbed changes nothing.
    #[test]
    fn merge_is_idempotent(ops in ops_strategy(3)) {
        let key = vault_key();
        let fork = VaultForkIds::new(&key);
        let (sets, _) = diverge(3, &ops);
        for set in &sets {
            prop_assert_eq!(
                fingerprint(&join(set, set, &fork)),
                fingerprint(set),
                "a ⊕ a != a"
            );
        }
        let (a, b) = (&sets[0], &sets[1]);
        let once = join(a, b, &fork);
        prop_assert_eq!(
            fingerprint(&join(&once, b, &fork)),
            fingerprint(&once),
            "(a ⊕ b) ⊕ b != a ⊕ b"
        );
    }

    /// Every application order produces byte-identical state — the property as
    /// SPEC §4 words it.
    #[test]
    fn every_application_order_converges(ops in ops_strategy(3)) {
        let key = vault_key();
        let fork = VaultForkIds::new(&key);
        let (sets, _) = diverge(3, &ops);
        let expected = fingerprint(&join_all(sets.iter(), &fork));
        // All six orderings of three states.
        let orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
        for order in orders {
            let ordered: Vec<&ItemSet> = order.iter().map(|index| &sets[*index]).collect();
            prop_assert_eq!(
                fingerprint(&join_all(ordered, &fork)),
                expected.clone(),
                "order {:?} diverged",
                order
            );
        }
    }

    /// The same, one item at a time rather than one whole set at a time: absorbing
    /// a peer's items in any order must give the same result.
    #[test]
    fn absorbing_items_in_any_order_converges(ops in ops_strategy(3), rotate in 0usize..8) {
        let key = vault_key();
        let fork = VaultForkIds::new(&key);
        let (sets, _) = diverge(3, &ops);
        let base = &sets[0];
        let incoming: Vec<_> = sets[1].iter().cloned().collect();

        let straight = join(base, &sets[1], &fork);
        let mut rotated = base.clone();
        let split = rotate % incoming.len().max(1);
        for item in incoming.iter().skip(split).chain(incoming.iter().take(split)) {
            rotated
                .absorb(item.clone(), &fork, &mut Vec::new())
                .expect("absorb");
        }
        prop_assert_eq!(
            fingerprint(&rotated),
            fingerprint(&straight),
            "absorbing in a rotated order diverged"
        );
    }
}

/// A regression guard with no randomness: the fork path is where associativity is
/// easiest to lose, so the three-way divergent-secret case is pinned explicitly as
/// well as being reachable by the generator above.
#[test]
fn three_divergent_secrets_converge_from_every_direction() {
    let key = vault_key();
    let fork = VaultForkIds::new(&key);
    let seeds = [0u8, 1, 2, 3];
    let mut genesis = peer(0, &seeds, NOW);
    let id = genesis
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");

    let secrets: [&[u8]; 3] = [b"aaaaaaaaaa", b"bbbbbbbbbb", b"cccccccccc"];
    let mut sets = Vec::new();
    for (index, secret) in secrets.iter().enumerate() {
        let seed = u8::try_from(index + 1).expect("small");
        let mut vault = peer(seed, &seeds, NOW);
        sync(&genesis, &mut vault);
        vault
            .repair_secret(&id, SecretBytes::from_slice(secret))
            .expect("repair");
        sets.push(vault.item_set().clone());
    }

    let expected = fingerprint(&join_all(sets.iter(), &fork));
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let ordered: Vec<&ItemSet> = order.iter().map(|index| &sets[*index]).collect();
        assert_eq!(
            fingerprint(&join_all(ordered, &fork)),
            expected,
            "order {order:?} diverged"
        );
    }
    // Three credentials, three items — none discarded.
    assert_eq!(join_all(sets.iter(), &fork).len(), 3);
}
