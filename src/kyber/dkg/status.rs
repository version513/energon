use super::structs::Node;
use crate::traits::Scheme;
use std::collections::HashMap;

pub(super) const SUCCESS: bool = true;
pub(super) const COMPLAINT: bool = false;

pub(super) type BitSet = HashMap<u32, bool>;
pub(super) struct StatusMatrix(HashMap<u32, BitSet>);

impl StatusMatrix {
    pub fn new<S: Scheme>(dealers: &[Node<S>], share_holders: &[Node<S>], status: bool) -> Self {
        let mut statuses = HashMap::new();

        for dealer in dealers {
            let mut bitset: BitSet = HashMap::new();
            for holder in share_holders {
                bitset.insert(holder.index, status);
            }
            statuses.insert(dealer.index, bitset);
        }

        StatusMatrix(statuses)
    }

    pub fn set(&mut self, dealer: u32, share: u32, status: bool) {
        self.0.entry(dealer).or_default().insert(share, status);
    }

    pub fn set_all(&mut self, dealer: &u32, new_status: bool) {
        if let Some(share) = self.0.get_mut(dealer) {
            for status in share.values_mut() {
                *status = new_status;
            }
        }
    }

    pub fn statuses_for_share(&self, share_index: u32) -> BitSet {
        let mut bt = BitSet::new();
        for (dealer_idx, bs) in self.0.iter() {
            if let Some(status) = bs.get(&share_index) {
                bt.insert(*dealer_idx, *status);
            }
        }
        bt
    }

    pub fn all_true(&self, dealer: &u32) -> bool {
        match self.0.get(dealer) {
            Some(map) => !map.values().any(|&status| status == COMPLAINT),
            None => false,
        }
    }

    pub fn complete_success(&self) -> bool {
        !self
            .0
            .values()
            .any(|dealer| dealer.values().any(|status| *status == COMPLAINT))
    }
}
