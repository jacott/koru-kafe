pub fn partition_list<T: std::fmt::Debug>(
    list: &mut [T],
    mut is_right: impl FnMut(&T, usize, Option<&T>) -> bool,
) -> usize {
    if list.is_empty() {
        return 0;
    }
    let mut left = 0;
    let mut right = list.len() - 1;

    while left <= right {
        while is_right(&list[right], right, None) {
            if right == 0 {
                return 0;
            }
            right -= 1;
        }

        if left >= right {
            return right + 1;
        }

        while !is_right(&list[left], left, Some(&list[right])) {
            left += 1;
            if left == right {
                return left + 1;
            }
        }

        list.swap(left, right);

        left += 1;
        right -= 1;
    }

    left
}

#[cfg(test)]
#[path = "util_test.rs"]
mod test;
