use super::*;

#[test]
fn test_default_initialization() {
    let manager: SlotMap<String> = SlotMap::default();
    // Index 0 is reserved for control, so we expect CAPACITY - 1 available IDs
    assert_eq!(manager.free_ids.len(), CAPACITY - 1);
    assert!(manager.get(Slot::control()).is_none());
}

#[test]
fn test_insert_and_get() {
    let mut manager = SlotMap::default();
    let data = "session_1".to_string();

    let slot = manager.insert(data.clone()).expect("Should have capacity");

    // Verify we can retrieve it
    assert_eq!(manager.get(slot), Some(&data));
    // Verify the slot is not the control slot (index 0)
    assert_ne!(slot, Slot::control());
}

#[test]
fn test_remove_and_recycle_fifo() {
    let mut manager = SlotMap::default();

    // 1. Insert two items
    let slot_a = manager.insert("A").unwrap();
    let _slot_b = manager.insert("B").unwrap();

    // 2. Remove A
    let removed_a = manager.remove(slot_a);
    assert_eq!(removed_a, Some("A"));

    // 3. Verify A is gone
    assert!(manager.get(slot_a).is_none());

    // 4. Fill the rest of the capacity to force recycling
    // (In a real test, we'd loop until full, but here we can check the free_ids queue)
    assert_eq!(*manager.free_ids.back().unwrap(), slot_a.as_u16());
}

#[test]
fn test_capacity_exhaustion() {
    let mut manager = SlotMap::<i32>::default();

    // Fill every available slot (CAPACITY - 1)
    for i in 1..CAPACITY {
        if manager.insert(i as i32).is_none() {
            panic!("i was {i}");
        }
    }

    // The next insert should fail
    assert!(manager.insert(999).is_none());
}

#[test]
fn test_double_remove() {
    let mut manager = SlotMap::default();
    let slot = manager.insert("data").unwrap();

    assert!(manager.remove(slot).is_some());
    // Second removal should return None and not corrupt the free_ids list
    assert!(manager.remove(slot).is_none());
}

#[test]
fn test_session_slot_conversions() {
    let slot = Slot::from(42u16);
    assert_eq!(slot.as_u16(), 42);
    assert_eq!(Slot::control().as_u16(), 0);
}
