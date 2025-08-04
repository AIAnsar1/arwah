use crate::input::{ArwahPortRange, ArwahScanOrder};
use crate::strategy::range::ArwahRange;
use rand::rng;
use rand::seq::SliceRandom;

#[derive(Debug)]
pub struct ArwahSerialRange {
    start: u16,
    end: u16,
}

#[derive(Debug)]
pub struct ArwahRandomRange {
    start: u16,
    end: u16,
}

#[derive(Debug)]
pub enum ArwahStrategy {
    Manual(Vec<u16>),
    Serial(ArwahSerialRange),
    Random(ArwahRandomRange),
}

trait ArwahRangeOrder {
    fn arwah_generate(&self) -> Vec<u16>;
}

impl ArwahStrategy {
    pub fn arwah_pick(range: &Option<ArwahPortRange>, ports: Option<Vec<u16>>, order: ArwahScanOrder) -> Self {
        match order {
            ArwahScanOrder::Serial if ports.is_none() => {
                let range = range.as_ref().unwrap();
                ArwahStrategy::Serial(ArwahSerialRange { start: range.start, end: range.end })
            }
            ArwahScanOrder::Random if ports.is_none() => {
                let range = range.as_ref().unwrap();
                ArwahStrategy::Random(ArwahRandomRange { start: range.start, end: range.end })
            }
            ArwahScanOrder::Serial => ArwahStrategy::Manual(ports.unwrap()),
            ArwahScanOrder::Random => {
                let mut rng = rng();
                let mut ports = ports.unwrap();
                ports.shuffle(&mut rng);
                ArwahStrategy::Manual(ports)
            }
        }
    }

    pub fn arwah_order(&self) -> Vec<u16> {
        match self {
            ArwahStrategy::Manual(ports) => ports.clone(),
            ArwahStrategy::Serial(range) => range.arwah_generate(),
            ArwahStrategy::Random(range) => range.arwah_generate(),
        }
    }
}

impl ArwahRangeOrder for ArwahSerialRange {
    fn arwah_generate(&self) -> Vec<u16> {
        (self.start..=self.end).collect()
    }
}

impl ArwahRangeOrder for ArwahRandomRange {
    fn arwah_generate(&self) -> Vec<u16> {
        ArwahRange::arwah_new(self.start.into(), self.end.into()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{ArwahPortRange, ArwahScanOrder};

    #[test]
    fn serial_strategy_with_range() {
        let range = ArwahPortRange { start: 1, end: 100 };
        let strategy = ArwahStrategy::arwah_pick(&Some(range), None, ArwahScanOrder::Serial);
        let result = strategy.arwah_order();
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);
    }
    #[test]
    fn random_strategy_with_range() {
        let range = ArwahPortRange { start: 1, end: 100 };
        let strategy = ArwahStrategy::arwah_pick(&Some(range), None, ArwahScanOrder::Random);
        let mut result = strategy.arwah_order();
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_ne!(expected_range, result);

        result.sort_unstable();
        assert_eq!(expected_range, result);
    }

    #[test]
    fn serial_strategy_with_ports() {
        let strategy = ArwahStrategy::arwah_pick(&None, Some(vec![80, 443]), ArwahScanOrder::Serial);
        let result = strategy.arwah_order();
        assert_eq!(vec![80, 443], result);
    }

    #[test]
    fn random_strategy_with_ports() {
        let strategy = ArwahStrategy::arwah_pick(&None, Some((1..10).collect()), ArwahScanOrder::Random);
        let mut result = strategy.arwah_order();
        let expected_range = (1..10).collect::<Vec<u16>>();
        assert_ne!(expected_range, result);

        result.sort_unstable();
        assert_eq!(expected_range, result);
    }
}
