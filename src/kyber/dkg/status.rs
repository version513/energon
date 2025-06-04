use super::structs::Node;
use crate::traits::Scheme;
use std::collections::BTreeMap;

pub const SUCCESS: bool = true;
pub const COMPLAINT: bool = false;

pub type BitSet = BTreeMap<u32, bool>;

#[derive(Clone)]
pub struct StatusMatrix(BTreeMap<u32, BitSet>);

impl StatusMatrix {
    pub fn new<S: Scheme>(dealers: &[Node<S>], share_holders: &[Node<S>], status: bool) -> Self {
        StatusMatrix(
            dealers
                .iter()
                .map(|dealer| {
                    let bitset = share_holders
                        .iter()
                        .map(|holder| (holder.index, status))
                        .collect();
                    (dealer.index, bitset)
                })
                .collect(),
        )
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
        self.0
            .iter()
            .filter_map(|(dealer_idx, bs)| {
                bs.get(&share_index).map(|status| (*dealer_idx, *status))
            })
            .collect()
    }

    pub fn status_of_dealer(&self, dealer_index: &u32) -> &BTreeMap<u32, bool> {
        self.0.get(dealer_index).unwrap()
    }

    pub fn all_true(&self, dealer: &u32) -> bool {
        self.0.get(dealer).map_or(false, |map| {
            !map.values().any(|&status| status == COMPLAINT)
        })
    }

    pub fn complete_success(&self) -> bool {
        !self
            .0
            .values()
            .any(|dealer| dealer.values().any(|status| *status == COMPLAINT))
    }
}

pub fn length_complaints(b: &BitSet) -> u32 {
    b.iter().filter(|&(_, status)| *status == COMPLAINT).count() as u32
}
