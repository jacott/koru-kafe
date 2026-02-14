use super::*;

#[test]
fn test_default_initialization() {
    let map: SlotMap<String> = SlotMap::default();
    // Index 0 is reserved for control, so we expect CAPACITY - 1 available IDs
    assert_eq!(map.free_ids.len(), CAPACITY - 1);
    assert!(map.get(Slot::control()).is_none());
}

#[test]
fn test_insert_and_get() {
    let mut map = SlotMap::default();
    let data = "session_1".to_string();

    let slot = map.insert(data.clone()).expect("Should have capacity");

    // Verify we can retrieve it
    assert_eq!(map.get(slot), Some(&data));
    // Verify the slot is not the control slot (index 0)
    assert_ne!(slot, Slot::control());
}

#[test]
fn test_remove_and_recycle_fifo() {
    let mut map = SlotMap::default();

    // 1. Insert two items
    let slot_a = map.insert("A").unwrap();
    let _slot_b = map.insert("B").unwrap();

    // 2. Remove A
    let removed_a = map.remove(slot_a);
    assert_eq!(removed_a, Some("A"));

    // 3. Verify A is gone
    assert!(map.get(slot_a).is_none());

    // 4. Fill the rest of the capacity to force recycling
    // (In a real test, we'd loop until full, but here we can check the free_ids queue)
    assert_eq!(*map.free_ids.back().unwrap(), slot_a.as_u16());
}

#[test]
fn clear() {
    let mut map = SlotMap::default();

    // 1. Insert two items
    let slot_a = map.insert("A").unwrap();
    let slot_b = map.insert("B").unwrap();

    assert_eq!(*map.free_ids.back().unwrap(), 65535);
    assert_eq!(*map.free_ids.front().unwrap(), 3);

    map.clear();
    assert_eq!(map.len(), 0);
    assert_eq!(*map.free_ids.front().unwrap(), 3);
    assert_eq!(*map.free_ids.get(1).unwrap(), 4);
    assert_eq!(*map.free_ids.get(2).unwrap(), 5);
    assert_eq!(*map.free_ids.back().unwrap(), 2);
    assert_eq!(*map.free_ids.get(65534).unwrap(), 2);
    assert_eq!(*map.free_ids.get(65533).unwrap(), 1);
    assert_eq!(*map.free_ids.get(65532).unwrap(), 65535);
    assert_eq!(*map.free_ids.get(65531).unwrap(), 65534);

    assert!(map.get(slot_a).is_none());
    assert!(map.get(slot_b).is_none());
}

#[test]
fn test_capacity_exhaustion() {
    let mut map = SlotMap::<i32>::default();

    // Fill every available slot (CAPACITY - 1)
    for i in 1..CAPACITY {
        if map.insert(i as i32).is_none() {
            panic!("i was {i}");
        }
    }

    // The next insert should fail
    assert!(map.insert(999).is_none());
}

#[test]
fn test_double_remove() {
    let mut map = SlotMap::default();
    let slot = map.insert("data").unwrap();

    assert!(map.remove(slot).is_some());
    // Second removal should return None and not corrupt the free_ids list
    assert!(map.remove(slot).is_none());
}

#[test]
fn test_session_slot_conversions() {
    let slot = Slot::from(42u16);
    assert_eq!(slot.as_u16(), 42);
    assert_eq!(Slot::control().as_u16(), 0);
}
