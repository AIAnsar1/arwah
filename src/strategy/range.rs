use gcd::Gcd;
use rand::Rng;
use std::convert::TryInto;

pub struct ArwahRange {
    active: bool,
    normalized_end: u32,
    normalized_first_pick: u32,
    normalized_pick: u32,
    actual_start: u32,
    step: u32,
}

impl ArwahRange {
    pub fn arwah_new(start: u32, end: u32) -> Self {
        let normalized_end = end - start + 1;
        let step = arwah_pick_random_coprime(normalized_end);
        let mut rng = rand::rng();
        let normalized_first_pick = rng.random_range(0..normalized_end);

        Self { active: true, normalized_end, step, normalized_first_pick, normalized_pick: normalized_first_pick, actual_start: start }
    }
}

impl Iterator for ArwahRange {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.active {
            return None;
        }
        let current_pick = self.normalized_pick;
        let next_pick = (current_pick + self.step) % self.normalized_end;

        if next_pick == self.normalized_first_pick {
            self.active = false;
        }
        self.normalized_pick = next_pick;

        Some((self.actual_start + current_pick).try_into().expect("[ ETA ]: Could not convert u32 to u16"))
    }
}

fn arwah_pick_random_coprime(end: u32) -> u32 {
    let range_boundary = end / 4;
    let lower_range = range_boundary;
    let uper_range = end - range_boundary;
    let mut rng = rand::rng();
    let mut candidate = rng.random_range(lower_range..uper_range);

    for _ in 0..10 {
        if end.gcd(candidate) == 1 {
            return candidate;
        }
        candidate = rng.random_range(lower_range..uper_range);
    }
    end - 1
}

#[cfg(test)]
mod tests {
    use super::ArwahRange;

    #[test]
    fn test_range_iterator_iterates_through_the_entire_range() {
        let result = test_arwah_generate_sorted_range(1, 10);
        let expected_range = (1..=10).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);

        let result = test_arwah_generate_sorted_range(1, 100);
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);

        let result = test_arwah_generate_sorted_range(1, 1000);
        let expected_range = (1..=1000).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);

        let result = test_arwah_generate_sorted_range(1, 65535);
        let expected_range = (1..=65535).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);

        let result = test_arwah_generate_sorted_range(1000, 2000);
        let expected_range = (1000..=2000).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);
    }

    fn test_arwah_generate_sorted_range(start: u32, end: u32) -> Vec<u16> {
        let range = ArwahRange::arwah_new(start, end);
        let mut result = range.into_iter().collect::<Vec<u16>>();
        result.sort_unstable();
        result
    }
}
