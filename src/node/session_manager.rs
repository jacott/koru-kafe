use std::collections::VecDeque;

// fixme! rename this module to super::slot_map

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slot(usize);
impl Slot {
    pub fn control() -> Self {
        Self(0)
    }
    pub fn as_u16(&self) -> u16 {
        self.0 as u16
    }

    pub(crate) fn is_control(&self) -> bool {
        self.0 == 0
    }
}
impl From<u16> for Slot {
    fn from(value: u16) -> Self {
        Self(value as usize)
    }
}
impl From<Slot> for usize {
    fn from(value: Slot) -> Self {
        value.0
    }
}

const CAPACITY: usize = 1 << 16;

pub struct SlotMap<T> {
    // A fixed-size heap-allocated array for O(1) lookups
    slots: Box<[Option<T>; CAPACITY]>,
    // FIFO queue to ensure "cold" ID reuse
    free_ids: VecDeque<u16>,
}
impl<T> Default for SlotMap<T> {
    fn default() -> Self {
        let free_ids = (1..=(CAPACITY - 1) as u16).collect::<VecDeque<u16>>();

        // 1. Create a Vec (heap allocated)
        let mut v = Vec::with_capacity(CAPACITY);
        for _ in 0..CAPACITY {
            v.push(None);
        }

        // 2. Convert Vec to Boxed Slice, then try to turn it into the fixed-size Box
        let boxed_slice = v.into_boxed_slice();
        let slots: Box<[Option<T>; CAPACITY]> = match boxed_slice.try_into() {
            Ok(array) => array,
            Err(_) => unreachable!(),
        };

        // Create the array on the heap
        // Note: Using a macro or vec for initialization to avoid stack overflow
        Self { slots, free_ids }
    }
}
impl<T> SlotMap<T> {
    pub fn insert(&mut self, session: T) -> Option<Slot> {
        // Pop the "oldest" dead ID

        if let Some(id) = self.free_ids.pop_front() {
            self.slots[id as usize] = Some(session);
            Some(Slot(id as usize))
        } else {
            None // Map is 100% full
        }
    }

    pub fn remove(&mut self, id: Slot) -> Option<T> {
        if let Some(session) = self.slots[id.0].take() {
            // Push to the BACK so it's the last to be reused
            self.free_ids.push_back(id.0 as u16);
            Some(session)
        } else {
            None
        }
    }

    pub fn clear(&mut self) {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.take().is_some() {
                self.free_ids.push_back(i as u16);
                if CAPACITY - 1 == self.free_ids.len() {
                    break;
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        CAPACITY - 1 - self.free_ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, id: Slot) -> Option<&T> {
        self.slots.get(id.0)?.as_ref()
    }
}

#[cfg(test)]
#[path = "session_manager_test.rs"]
mod test;
