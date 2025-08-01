use std::time::Instant;

#[derive(Debug)]
pub struct ArwahNamedTimer {
    name: &'static str,
    start: Option<Instant>,
    end: Option<Instant>,
}

#[derive(Debug)]
pub struct ArwahBenchmark {
    named_timers: Vec<ArwahNamedTimer>,
}

impl ArwahNamedTimer {
    pub fn arwah_start(name: &'static str) -> Self {
        Self {
            name,
            start: Some(Instant::now()),
            end: None,
        }
    }

    pub fn arwah_end(&mut self) {
        self.end = Some(Instant::now());
    }
}

impl ArwahBenchmark {
    pub fn arwah_init() -> Self {
        Self {
            named_timers: Vec::new(),
        }
    }

    pub fn arwah_push(&mut self, timer: ArwahNamedTimer) {
        self.named_timers.push(timer);
    }

    pub fn arwah_summary(&self) -> String {
        let mut summary = String::from("\nArwah Benchmark Summary");

        for timer in &self.named_timers {
            if timer.start.is_some() && timer.end.is_some() {
                let runtime_secs = timer
                    .end
                    .unwrap()
                    .saturating_duration_since(timer.start.unwrap())
                    .as_secs_f32();
                summary.push_str(&format!("\n{0: <10} | {1: <10}s", timer.name, runtime_secs));
            }
        }
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark() {
        let mut benchmark = ArwahBenchmark::arwah_init();
        let mut test_timer = ArwahNamedTimer::arwah_start("test");
        std::thread::sleep(std::time::Duration::from_millis(100));
        test_timer.arwah_end();
        benchmark.arwah_push(test_timer);
        benchmark.arwah_push(ArwahNamedTimer::arwah_start("only_start"));
        assert!(
            benchmark
                .arwah_summary()
                .contains("\nArwah Benchmark Summary\ntest       | 0.")
        );
        assert!(!benchmark.arwah_summary().contains("only_test"));
    }
}
