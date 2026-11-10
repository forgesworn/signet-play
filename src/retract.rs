//! Taking back the notes an earlier version published.
//!
//! The persona signs one kind 5 (NIP-09) with **`e` tags only**: no `a`, `k`
//! or `d` tag, and empty content. Nothing in it names the game (kit
//! rule 1: a retraction is a kind 5 with `e` tags only).

use std::collections::BTreeSet;

use nostr::{Event, EventBuilder, EventId, Kind, PublicKey, Tag, Timestamp, UnsignedEvent};

/// The unsigned retraction of the events `ids`, for `persona` to sign.
pub fn unsigned_retraction(persona: &PublicKey, ids: &[EventId], now: u64) -> UnsignedEvent {
    let tags: Vec<Tag> = ids
        .iter()
        .map(|id| Tag::parse(["e", id.to_hex().as_str()]).expect("two-element tag always parses"))
        .collect();
    EventBuilder::new(Kind::EventDeletion, "")
        .tags(tags)
        .custom_created_at(Timestamp::from(now))
        .build(*persona)
}

/// Whether `ev` is exactly a retraction of `ids` by `persona`: kind 5, signed,
/// empty content, and nothing but one `["e", id]` tag per id.
pub fn is_clean_retraction(ev: &Event, persona: &PublicKey, ids: &[EventId]) -> bool {
    if ev.kind != Kind::EventDeletion
        || ev.pubkey != *persona
        || !ev.content.is_empty()
        || ev.verify().is_err()
    {
        return false;
    }
    let mut named: BTreeSet<String> = BTreeSet::new();
    for t in ev.tags.iter() {
        let s = t.as_slice();
        if s.len() != 2 || s[0] != "e" {
            return false;
        }
        named.insert(s[1].clone());
    }
    named == ids.iter().map(|i| i.to_hex()).collect::<BTreeSet<_>>() && named.len() == ev.tags.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    fn ids(n: u8) -> Vec<EventId> {
        (0..n)
            .map(|i| EventId::from_byte_array([i + 1; 32]))
            .collect()
    }

    #[test]
    fn a_retraction_has_e_tags_only_and_no_content() {
        let persona = Keys::generate();
        let want = ids(3);
        let ev = unsigned_retraction(&persona.public_key(), &want, 1_800_000_000)
            .sign_with_keys(&persona)
            .unwrap();
        assert_eq!(ev.kind, Kind::EventDeletion);
        assert_eq!(ev.pubkey, persona.public_key());
        assert_eq!(ev.content, "");
        assert_eq!(ev.tags.len(), 3);
        for t in ev.tags.iter() {
            let s = t.as_slice();
            assert_eq!(s.len(), 2, "{s:?}");
            assert_eq!(s[0], "e", "no a, k or d tag: {s:?}");
        }
        assert!(is_clean_retraction(&ev, &persona.public_key(), &want));
    }

    #[test]
    fn anything_else_is_not_a_clean_retraction() {
        let persona = Keys::generate();
        let want = ids(2);
        let sign = |b: EventBuilder| b.sign_with_keys(&persona).unwrap();
        let e = |i: &EventId| Tag::parse(["e", i.to_hex().as_str()]).unwrap();
        // A `k` tag, an `a` tag, content, a missing or extra id, another author, another kind.
        let with_k = sign(EventBuilder::new(Kind::EventDeletion, "").tags([
            e(&want[0]),
            e(&want[1]),
            Tag::parse(["k", "30420"]).unwrap(),
        ]));
        assert!(!is_clean_retraction(&with_k, &persona.public_key(), &want));
        let with_a = sign(EventBuilder::new(Kind::EventDeletion, "").tags([
            e(&want[0]),
            e(&want[1]),
            Tag::parse(["a", "30420:x:y"]).unwrap(),
        ]));
        assert!(!is_clean_retraction(&with_a, &persona.public_key(), &want));
        let with_content = sign(
            EventBuilder::new(Kind::EventDeletion, "removing").tags([e(&want[0]), e(&want[1])]),
        );
        assert!(!is_clean_retraction(
            &with_content,
            &persona.public_key(),
            &want
        ));
        let missing = sign(EventBuilder::new(Kind::EventDeletion, "").tags([e(&want[0])]));
        assert!(!is_clean_retraction(&missing, &persona.public_key(), &want));
        let extra = sign(EventBuilder::new(Kind::EventDeletion, "").tags([
            e(&want[0]),
            e(&want[1]),
            e(&ids(3)[2]),
        ]));
        assert!(!is_clean_retraction(&extra, &persona.public_key(), &want));
        let ok = sign(EventBuilder::new(Kind::EventDeletion, "").tags([e(&want[0]), e(&want[1])]));
        assert!(!is_clean_retraction(
            &ok,
            &Keys::generate().public_key(),
            &want
        ));
        let note = sign(EventBuilder::new(Kind::TextNote, "").tags([e(&want[0]), e(&want[1])]));
        assert!(!is_clean_retraction(&note, &persona.public_key(), &want));
        assert!(is_clean_retraction(&ok, &persona.public_key(), &want));
    }
}
