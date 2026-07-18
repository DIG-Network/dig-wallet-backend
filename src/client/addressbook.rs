//! `client::addressbook` — local contacts + labels (SPEC §4).
//!
//! A small piece of dig-app-local state: user-assigned labels for addresses so the review UI
//! can show "Send to Alice" instead of a raw `xch1…`. Pure local state; no network, no keys.

use std::collections::BTreeMap;

use crate::types::Address;

/// A label → address contact book, kept dig-app-side.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressBook {
    contacts: BTreeMap<String, Address>,
}

impl AddressBook {
    /// An empty address book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a contact, returning the previous address for that label if any.
    pub fn set(&mut self, label: impl Into<String>, address: Address) -> Option<Address> {
        self.contacts.insert(label.into(), address)
    }

    /// Look up the address for a label.
    pub fn get(&self, label: &str) -> Option<&Address> {
        self.contacts.get(label)
    }

    /// Find the first label mapped to `address` (for rendering "Send to <label>").
    pub fn label_for(&self, address: &Address) -> Option<&str> {
        self.contacts
            .iter()
            .find(|(_, a)| *a == address)
            .map(|(l, _)| l.as_str())
    }

    /// Remove a contact, returning its address if it existed.
    pub fn remove(&mut self, label: &str) -> Option<Address> {
        self.contacts.remove(label)
    }

    /// The contacts, ordered by label.
    pub fn entries(&self) -> impl Iterator<Item = (&String, &Address)> {
        self.contacts.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_and_label_for_round_trip() {
        let mut book = AddressBook::new();
        assert!(book.set("Alice", Address("xch1alice".into())).is_none());
        assert_eq!(book.get("Alice"), Some(&Address("xch1alice".into())));
        assert_eq!(book.label_for(&Address("xch1alice".into())), Some("Alice"));
    }

    #[test]
    fn set_replaces_and_returns_previous() {
        let mut book = AddressBook::new();
        book.set("Bob", Address("xch1old".into()));
        let prev = book.set("Bob", Address("xch1new".into()));
        assert_eq!(prev, Some(Address("xch1old".into())));
        assert_eq!(book.get("Bob"), Some(&Address("xch1new".into())));
    }

    #[test]
    fn remove_deletes_a_contact() {
        let mut book = AddressBook::new();
        book.set("Carol", Address("xch1carol".into()));
        assert_eq!(book.remove("Carol"), Some(Address("xch1carol".into())));
        assert!(book.get("Carol").is_none());
        assert!(book.remove("Carol").is_none());
    }

    #[test]
    fn entries_are_ordered_by_label() {
        let mut book = AddressBook::new();
        book.set("Zoe", Address("z".into()));
        book.set("Ann", Address("a".into()));
        let labels: Vec<_> = book.entries().map(|(l, _)| l.clone()).collect();
        assert_eq!(labels, vec!["Ann".to_string(), "Zoe".to_string()]);
    }

    #[test]
    fn label_for_unknown_address_is_none() {
        let book = AddressBook::new();
        assert!(book.label_for(&Address("nope".into())).is_none());
    }
}
