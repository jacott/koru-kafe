use super::*;

#[test]
fn empty() {
    let mut list: [u8; 0] = [];
    let idx = partition_list::<u8>(&mut list, |_, _, _| unreachable!());

    assert_eq!(idx, 0);
    assert!(list.is_empty());
}

#[test]
fn one_left() {
    let mut tests = vec![];
    let mut list = [1];
    let idx = partition_list::<u8>(&mut list, |v, i, _| {
        tests.push((*v, i));
        false
    });

    assert_eq!(idx, 1);
    assert_eq!(&list, &[1]);
    assert_eq!(tests, [(1, 0)])
}

#[test]
fn one_right() {
    let mut tests = vec![];
    let mut list = [1];
    let idx = partition_list::<u8>(&mut list, |v, i, _| {
        tests.push((*v, i));
        true
    });

    assert_eq!(idx, 0);
    assert_eq!(&list, &[1]);
    assert_eq!(tests, [(1, 0)])
}

#[test]
fn all_left() {
    let mut tests = vec![];
    let mut list = [1, 2, 3];
    let idx = partition_list::<u8>(&mut list, |v, i, other| {
        tests.push((*v, i, other.cloned()));
        false
    });

    assert_eq!(idx, 3);
    assert_eq!(&list, &[1, 2, 3]);
    assert_eq!(tests, [(3, 2, None), (1, 0, Some(3)), (2, 1, Some(3))])
}

#[test]
fn all_right() {
    let mut tests = vec![];
    let mut list = [1, 2, 3];
    let idx = partition_list::<u8>(&mut list, |v, i, other| {
        tests.push((*v, i, other.cloned()));
        true
    });

    assert_eq!(idx, 0);
    assert_eq!(&list, &[1, 2, 3]);
    assert_eq!(tests, [(3, 2, None), (2, 1, None), (1, 0, None)])
}

#[test]
fn odd_right() {
    let mut tests = vec![];
    let mut list = [1, 2, 3, 4, 5, 6];
    let idx = partition_list::<u8>(&mut list, |v, i, _| {
        tests.push((*v, i));
        (v & 1) == 1
    });

    assert_eq!(idx, 3);
    assert_eq!(&list, &[6, 2, 4, 3, 5, 1]);
    assert_eq!(tests, [(6, 5), (1, 0), (5, 4), (4, 3), (2, 1), (3, 2)])
}

#[test]
fn odd_right_odd() {
    let mut tests = vec![];
    let mut list = [1, 2, 3, 4, 5];
    let idx = partition_list::<u8>(&mut list, |v, i, _| {
        tests.push((*v, i));
        (v & 1) == 1
    });

    assert_eq!(idx, 2);
    assert_eq!(&list, &[4, 2, 3, 1, 5]);
    assert_eq!(tests, [(5, 4), (4, 3), (1, 0), (3, 2), (2, 1)])
}

#[test]
fn odd_left() {
    let mut tests = vec![];
    let mut list = [1, 2, 3, 4, 5, 6];
    let idx = partition_list::<u8>(&mut list, |v, i, _| {
        tests.push((*v, i));
        (v & 1) == 0
    });

    assert_eq!(idx, 3);
    assert_eq!(&list, &[1, 5, 3, 4, 2, 6]);
    assert_eq!(tests, [(6, 5), (5, 4), (1, 0), (2, 1), (4, 3), (3, 2)])
}

#[test]
fn test_trigger_partition_fixme() {
    let mut list = vec![10, 20, 30];

    let idx = partition_list(&mut list, |_val, idx, context| {
        match (idx, context) {
            // Search from Right (context is None)
            (2, None) => false, // Stop right-search at index 2
            (1, None) => true,  // Skip index 1 (move right to 0)
            (0, None) => false, // Stop right-search at index 0

            // Search from Left (context is Some)
            (0, Some(_)) => true, // Swap index 0 in Iteration 1
            (1, Some(_)) => true, // Swap index 1 in Iteration 2

            _ => false,
        }
    });

    assert_eq!(idx, 1);
    assert_eq!(&list, &[30, 20, 10]);
}
