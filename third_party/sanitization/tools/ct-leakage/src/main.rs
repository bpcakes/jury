use sanitization::ct::{
    self, Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeOrd, PublicCtOption, PublicCtResult,
    SecretIndex,
};
use sanitization::SecretBytes;
use std::env;
use std::fs;
use std::hint::black_box;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CASES: &[Case] = &[
    Case {
        name: "ct_choice_boolean_ops",
        description: "Choice boolean operations false vs true input",
        run: run_choice_boolean_ops,
    },
    Case {
        name: "ct_eq_fixed_16_first_diff",
        description: "ct::eq_fixed([u8; 16]) equal vs first-byte difference",
        run: run_eq_fixed_16_first_diff,
    },
    Case {
        name: "ct_eq_fixed_32_first_diff",
        description: "ct::eq_fixed([u8; 32]) equal vs first-byte difference",
        run: run_eq_fixed_32_first_diff,
    },
    Case {
        name: "ct_eq_fixed_32_last_diff",
        description: "ct::eq_fixed([u8; 32]) equal vs last-byte difference",
        run: run_eq_fixed_32_last_diff,
    },
    Case {
        name: "ct_eq_fixed_64_last_diff",
        description: "ct::eq_fixed([u8; 64]) equal vs last-byte difference",
        run: run_eq_fixed_64_last_diff,
    },
    Case {
        name: "ct_eq_public_len_64_first_diff",
        description: "ct::eq_public_len([u8; 64]) equal vs first-byte difference",
        run: run_eq_public_len_64_first_diff,
    },
    Case {
        name: "secret_bytes_eq_32_first_diff",
        description: "SecretBytes<32>::ct_eq equal vs first-byte difference",
        run: run_secret_bytes_eq_32_first_diff,
    },
    Case {
        name: "ct_cmp_fixed_32_first_diff",
        description: "ct::cmp_fixed([u8; 32]) equal vs first-byte difference",
        run: run_cmp_fixed_32_first_diff,
    },
    Case {
        name: "ct_u64_ordering_equal_vs_different",
        description: "u64::ct_cmp equal vs different value",
        run: run_u64_ordering_equal_vs_different,
    },
    Case {
        name: "ct_u64_select_choice",
        description: "u64::conditional_select false Choice vs true Choice",
        run: run_u64_select_choice,
    },
    Case {
        name: "ct_option_unwrap_choice",
        description: "PublicCtOption<u64>::unwrap_or absent vs present Choice",
        run: run_ct_option_unwrap_choice,
    },
    Case {
        name: "ct_result_unwrap_choice",
        description: "PublicCtResult<u64, u64>::unwrap_or error vs success Choice",
        run: run_ct_result_unwrap_choice,
    },
    Case {
        name: "ct_conditional_copy_64_choice",
        description: "ct::conditional_copy([u8; 64]) false Choice vs true Choice",
        run: run_conditional_copy_64_choice,
    },
    Case {
        name: "ct_conditional_swap_64_choice",
        description: "ct::conditional_swap([u8; 64]) false Choice vs true Choice",
        run: run_conditional_swap_64_choice,
    },
    Case {
        name: "ct_select_slice_64_choice",
        description: "ct::select_slice([u8; 64]) false Choice vs true Choice",
        run: run_select_slice_64_choice,
    },
    Case {
        name: "ct_oblivious_lookup_16_index",
        description: "ct::oblivious_lookup([u8; 16]) low secret index vs high secret index",
        run: run_oblivious_lookup_16_index,
    },
];

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    description: &'static str,
    run: fn(Class, usize, &mut XorShift64) -> u128,
}

#[derive(Clone, Copy)]
enum Class {
    A,
    B,
}

#[derive(Clone)]
struct Config {
    seed: Option<u64>,
    samples: usize,
    inner: usize,
    warmup: usize,
    threshold: f64,
    case_filter: Option<String>,
    output: Option<String>,
}

#[derive(Default, Clone, Copy)]
struct Stats {
    count: u64,
    mean: f64,
    m2: f64,
}

impl Stats {
    fn push(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    fn variance(self) -> f64 {
        if self.count > 1 {
            self.m2 / (self.count - 1) as f64
        } else {
            0.0
        }
    }
}

#[derive(Clone)]
struct CaseResult {
    name: &'static str,
    description: &'static str,
    samples_a: u64,
    samples_b: u64,
    mean_a: f64,
    mean_b: f64,
    variance_a: f64,
    variance_b: f64,
    welch_t_abs: f64,
    threshold: f64,
    passed: bool,
}

#[derive(Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn fill<const N: usize>(&mut self) -> [u8; N] {
        let mut bytes = [0u8; N];
        let mut index = 0;
        while index < N {
            let word = self.next_u64().to_ne_bytes();
            for byte in word {
                if index == N {
                    break;
                }
                bytes[index] = byte;
                index += 1;
            }
        }
        bytes
    }
}

fn main() {
    let config = match parse_args() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!();
            print_usage();
            std::process::exit(2);
        }
    };

    if config.samples < 2 {
        eprintln!("--samples must be at least 2");
        std::process::exit(2);
    }

    let selected: Vec<Case> = CASES
        .iter()
        .copied()
        .filter(|case| {
            config
                .case_filter
                .as_ref()
                .is_none_or(|filter| case.name == filter)
        })
        .collect();

    if selected.is_empty() {
        eprintln!("no matching leakage case");
        print_cases();
        std::process::exit(2);
    }

    let seed = config.seed.unwrap_or_else(random_seed);
    let mut rng = XorShift64::new(seed);
    let mut results = Vec::new();

    for case in selected {
        for _ in 0..config.warmup {
            let class = if rng.next_u64() & 1 == 0 {
                Class::A
            } else {
                Class::B
            };
            black_box((case.run)(class, config.inner, &mut rng));
        }

        let mut stats_a = Stats::default();
        let mut stats_b = Stats::default();
        let schedule = balanced_class_schedule(config.samples, &mut rng);
        for class in schedule {
            let elapsed = (case.run)(class, config.inner, &mut rng) as f64;
            match class {
                Class::A => stats_a.push(elapsed),
                Class::B => stats_b.push(elapsed),
            }
        }

        let t_abs = welch_t_abs(stats_a, stats_b);
        results.push(CaseResult {
            name: case.name,
            description: case.description,
            samples_a: stats_a.count,
            samples_b: stats_b.count,
            mean_a: stats_a.mean,
            mean_b: stats_b.mean,
            variance_a: stats_a.variance(),
            variance_b: stats_b.variance(),
            welch_t_abs: t_abs,
            threshold: config.threshold,
            passed: t_abs <= config.threshold,
        });
    }

    let passed = results.iter().all(|result| result.passed);
    let report = render_report(&config, seed, passed, &results);

    if let Some(path) = &config.output {
        if let Err(error) = write_report(path, &report) {
            eprintln!("failed to write {path}: {error}");
            std::process::exit(1);
        }
    }

    println!("{report}");

    if passed {
        std::process::exit(0);
    }
    std::process::exit(1);
}

fn write_report(path: &str, report: &str) -> std::io::Result<()> {
    let path = Path::new(path);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, report)
}

fn parse_args() -> Result<Config, String> {
    parse_args_from(env::args().skip(1))
}

fn parse_args_from<I, S>(args: I) -> Result<Config, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut config = Config {
        seed: None,
        samples: 20_000,
        inner: 200,
        warmup: 1_000,
        threshold: 4.5,
        case_filter: None,
        output: None,
    };

    let mut args = args.into_iter().map(|arg| normalize_cli_arg(arg.into()));
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => config.seed = Some(parse_u64("--seed", args.next())?),
            "--samples" => config.samples = parse_usize("--samples", args.next())?,
            "--inner" => config.inner = parse_usize("--inner", args.next())?,
            "--warmup" => config.warmup = parse_usize("--warmup", args.next())?,
            "--threshold" => config.threshold = parse_f64("--threshold", args.next())?,
            "--case" => config.case_filter = Some(required_value("--case", args.next())?),
            "--output" => config.output = Some(required_value("--output", args.next())?),
            "--list" => {
                print_cases();
                std::process::exit(0);
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(config)
}

fn normalize_cli_arg(arg: String) -> String {
    arg.trim_matches(|character: char| {
        character.is_whitespace() || matches!(character, '\u{00a0}' | '\u{feff}')
    })
    .to_owned()
}

fn required_value(flag: &str, value: Option<String>) -> Result<String, String> {
    value.ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_usize(flag: &str, value: Option<String>) -> Result<usize, String> {
    required_value(flag, value)?
        .parse()
        .map_err(|_| format!("{flag} requires a positive integer"))
}

fn parse_u64(flag: &str, value: Option<String>) -> Result<u64, String> {
    required_value(flag, value)?
        .parse()
        .map_err(|_| format!("{flag} requires an unsigned integer"))
}

fn parse_f64(flag: &str, value: Option<String>) -> Result<f64, String> {
    required_value(flag, value)?
        .parse()
        .map_err(|_| format!("{flag} requires a number"))
}

fn print_usage() {
    eprintln!("usage: ct-leakage [--seed N] [--samples N] [--inner N] [--warmup N] [--threshold T] [--case NAME] [--output PATH]");
    eprintln!();
    print_cases();
}

fn print_cases() {
    eprintln!("available cases:");
    for case in CASES {
        eprintln!("  {:36} {}", case.name, case.description);
    }
}

fn random_seed() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0xA5A5_5A5A_F0F0_0F0F);
    now ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

fn welch_t_abs(left: Stats, right: Stats) -> f64 {
    let variance_left = left.variance();
    let variance_right = right.variance();
    let denominator =
        ((variance_left / left.count as f64) + (variance_right / right.count as f64)).sqrt();
    if denominator == 0.0 {
        if left.mean == right.mean {
            0.0
        } else {
            f64::INFINITY
        }
    } else {
        ((left.mean - right.mean) / denominator).abs()
    }
}

fn balanced_class_schedule(samples: usize, rng: &mut XorShift64) -> Vec<Class> {
    let count_a = samples / 2;
    let mut schedule = Vec::with_capacity(samples);
    schedule.extend(core::iter::repeat_n(Class::A, count_a));
    schedule.extend(core::iter::repeat_n(Class::B, samples - count_a));

    // Shuffle a pre-balanced schedule instead of forcing one class after the
    // other reaches its quota. A forced tail correlates class membership with
    // late-run frequency and scheduler drift, creating false leakage signals.
    let mut remaining = schedule.len();
    while remaining > 1 {
        let selected = (rng.next_u64() as usize) % remaining;
        schedule.swap(remaining - 1, selected);
        remaining -= 1;
    }

    schedule
}

fn measure(inner: usize, mut body: impl FnMut() -> u8) -> u128 {
    let start = read_counter();
    let mut acc = 0u8;
    for _ in 0..inner {
        acc ^= black_box(body());
    }
    black_box(acc);
    read_counter().saturating_sub(start)
}

fn run_choice_boolean_ops(class: Class, inner: usize, _rng: &mut XorShift64) -> u128 {
    let choice = choice_for_class(class);
    measure(inner, || {
        black_box(choice)
            .and(Choice::TRUE)
            .xor(Choice::FALSE)
            .or(Choice::FALSE)
            .declassify_u8("test or verification observes normalized choice")
    })
}

fn run_eq_fixed_16_first_diff(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let left = rng.fill::<16>();
    let mut right = left;
    if matches!(class, Class::B) {
        right[0] ^= 0x80;
    }
    measure(inner, || {
        ct::eq_fixed(black_box(&left), black_box(&right))
            .declassify_u8("test or verification observes normalized choice")
    })
}

fn run_eq_fixed_32_first_diff(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let left = rng.fill::<32>();
    let mut right = left;
    if matches!(class, Class::B) {
        right[0] ^= 0x80;
    }
    measure(inner, || {
        ct::eq_fixed(black_box(&left), black_box(&right))
            .declassify_u8("test or verification observes normalized choice")
    })
}

fn run_eq_fixed_32_last_diff(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let left = rng.fill::<32>();
    let mut right = left;
    if matches!(class, Class::B) {
        right[31] ^= 0x01;
    }
    measure(inner, || {
        ct::eq_fixed(black_box(&left), black_box(&right))
            .declassify_u8("test or verification observes normalized choice")
    })
}

fn run_eq_fixed_64_last_diff(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let left = rng.fill::<64>();
    let mut right = left;
    if matches!(class, Class::B) {
        right[63] ^= 0x01;
    }
    measure(inner, || {
        ct::eq_fixed(black_box(&left), black_box(&right))
            .declassify_u8("test or verification observes normalized choice")
    })
}

fn run_eq_public_len_64_first_diff(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let left = rng.fill::<64>();
    let mut right = left;
    if matches!(class, Class::B) {
        right[0] ^= 0x40;
    }
    measure(inner, || {
        ct::eq_public_len(black_box(&left), black_box(&right))
            .declassify_u8("test or verification observes normalized choice")
    })
}

fn run_secret_bytes_eq_32_first_diff(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let left_bytes = rng.fill::<32>();
    let mut right_bytes = left_bytes;
    if matches!(class, Class::B) {
        right_bytes[0] ^= 0x80;
    }
    let left = SecretBytes::<32>::from_array(left_bytes);
    let right = SecretBytes::<32>::from_array(right_bytes);
    measure(inner, || {
        left.ct_eq(black_box(&right))
            .declassify_u8("test or verification observes normalized choice")
    })
}

fn run_cmp_fixed_32_first_diff(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let left = rng.fill::<32>();
    let mut right = left;
    if matches!(class, Class::B) {
        right[0] = right[0].wrapping_add(1);
    }
    measure(inner, || {
        let ordering = ct::cmp_fixed(black_box(&left), black_box(&right));
        ordering
            .is_less()
            .declassify_u8("test or verification observes normalized choice")
            ^ ordering
                .is_equal()
                .declassify_u8("test or verification observes normalized choice")
    })
}

fn run_u64_ordering_equal_vs_different(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let left = rng.next_u64();
    let right = match class {
        Class::A => left,
        Class::B => left ^ 0x8000_0000_0000_0001,
    };
    measure(inner, || {
        let ordering = black_box(left).ct_cmp(&black_box(right));
        ordering
            .is_less()
            .xor(ordering.is_equal())
            .declassify_u8("test or verification observes normalized choice")
    })
}

fn run_u64_select_choice(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let left = rng.next_u64();
    let right = rng.next_u64();
    let choice = choice_for_class(class);
    measure(inner, || {
        u64::conditional_select(black_box(&left), black_box(&right), black_box(choice)) as u8
    })
}

fn run_ct_option_unwrap_choice(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let value = rng.next_u64();
    let fallback = rng.next_u64();
    let option = PublicCtOption::new(value, choice_for_class(class));
    measure(inner, || option.unwrap_or(black_box(&fallback)) as u8)
}

fn run_ct_result_unwrap_choice(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let value = rng.next_u64();
    let error = rng.next_u64();
    let fallback = rng.next_u64();
    let result = PublicCtResult::new(value, error, choice_for_class(class));
    measure(inner, || result.unwrap_or(black_box(&fallback)) as u8)
}

fn run_conditional_copy_64_choice(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let mut destination = rng.fill::<64>();
    let source = rng.fill::<64>();
    let choice = choice_for_class(class);
    measure(inner, || {
        ct::conditional_copy(black_box(&mut destination), black_box(&source), choice).unwrap();
        destination[0]
    })
}

fn run_conditional_swap_64_choice(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let mut left = rng.fill::<64>();
    let mut right = rng.fill::<64>();
    let choice = choice_for_class(class);
    measure(inner, || {
        ct::conditional_swap(black_box(&mut left), black_box(&mut right), choice).unwrap();
        left[0] ^ right[0]
    })
}

fn run_select_slice_64_choice(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let mut destination = [0u8; 64];
    let left = rng.fill::<64>();
    let right = rng.fill::<64>();
    let choice = choice_for_class(class);
    measure(inner, || {
        ct::select_slice(
            black_box(&mut destination),
            black_box(&left),
            black_box(&right),
            choice,
        )
        .unwrap();
        destination[0]
    })
}

fn run_oblivious_lookup_16_index(class: Class, inner: usize, rng: &mut XorShift64) -> u128 {
    let table = rng.fill::<16>();
    let fallback = rng.next_u64() as u8;
    let index = match class {
        Class::A => 1usize,
        Class::B => 14usize,
    };
    measure(inner, || {
        ct::oblivious_lookup(
            black_box(&table),
            SecretIndex::new(index),
            black_box(&fallback),
        )
    })
}

fn choice_for_class(class: Class) -> Choice {
    match class {
        Class::A => Choice::FALSE,
        Class::B => Choice::TRUE,
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn read_counter() -> u128 {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{_mm_lfence, _rdtsc};
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{_mm_lfence, _rdtsc};

    unsafe {
        _mm_lfence();
        let value = _rdtsc() as u128;
        _mm_lfence();
        value
    }
}

#[cfg(all(target_arch = "aarch64", not(miri)))]
fn read_counter() -> u128 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "isb",
            "mrs {value}, cntvct_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value as u128
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
fn read_counter() -> u128 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos()
}

fn render_report(config: &Config, seed: u64, passed: bool, results: &[CaseResult]) -> String {
    let mut output = String::new();
    output.push_str("{\n");
    output.push_str("  \"schema_version\": 1,\n");
    output.push_str("  \"tool\": \"ct-leakage\",\n");
    push_json_field(
        &mut output,
        "generated_at_utc",
        &generated_at_utc(),
        true,
        2,
    );
    output.push_str("  \"passed\": ");
    output.push_str(if passed { "true" } else { "false" });
    output.push_str(",\n");
    output.push_str(&format!("  \"seed\": {seed},\n"));
    output.push_str("  \"config\": {\n");
    output.push_str(&format!("    \"samples\": {},\n", config.samples));
    output.push_str(&format!("    \"inner\": {},\n", config.inner));
    output.push_str(&format!("    \"warmup\": {},\n", config.warmup));
    output.push_str(&format!("    \"threshold\": {}\n", config.threshold));
    output.push_str("  },\n");
    output.push_str("  \"environment\": {\n");
    push_json_field(&mut output, "os", env::consts::OS, true, 4);
    push_json_field(&mut output, "arch", env::consts::ARCH, true, 4);
    push_json_field(&mut output, "family", env::consts::FAMILY, true, 4);
    push_json_field(
        &mut output,
        "rustc",
        &command_output("rustc", &["--version", "--verbose"]),
        true,
        4,
    );
    push_json_field(&mut output, "target", &rustc_host_target(), true, 4);
    push_json_field(&mut output, "profile", "release", true, 4);
    push_json_field(&mut output, "cpu", &cpu_description(), true, 4);
    push_json_field(
        &mut output,
        "uname",
        &command_output("uname", &["-a"]),
        true,
        4,
    );
    push_json_field(
        &mut output,
        "git_commit",
        &command_output("git", &["rev-parse", "HEAD"]),
        true,
        4,
    );
    push_json_field(&mut output, "features", &enabled_features(), true, 4);
    push_json_field(
        &mut output,
        "runner",
        &environment_value("RUNNER_NAME", "local"),
        true,
        4,
    );
    push_json_field(&mut output, "workflow_run", &workflow_run_url(), true, 4);
    push_json_field(
        &mut output,
        "cpu_affinity",
        &environment_value("SANITIZATION_EVIDENCE_CPU_AFFINITY", "not controlled"),
        true,
        4,
    );
    push_json_field(
        &mut output,
        "frequency_scaling",
        &environment_value("SANITIZATION_EVIDENCE_FREQUENCY", "not controlled"),
        true,
        4,
    );
    push_json_field(
        &mut output,
        "smt",
        &environment_value("SANITIZATION_EVIDENCE_SMT", "not controlled"),
        false,
        4,
    );
    output.push_str("  },\n");
    output.push_str("  \"cases\": [\n");
    for (index, result) in results.iter().enumerate() {
        output.push_str("    {\n");
        push_json_field(&mut output, "name", result.name, true, 6);
        push_json_field(&mut output, "description", result.description, true, 6);
        output.push_str(&format!("      \"samples_a\": {},\n", result.samples_a));
        output.push_str(&format!("      \"samples_b\": {},\n", result.samples_b));
        output.push_str(&format!("      \"mean_a\": {:.6},\n", result.mean_a));
        output.push_str(&format!("      \"mean_b\": {:.6},\n", result.mean_b));
        output.push_str(&format!(
            "      \"variance_a\": {:.6},\n",
            result.variance_a
        ));
        output.push_str(&format!(
            "      \"variance_b\": {:.6},\n",
            result.variance_b
        ));
        output.push_str(&format!(
            "      \"welch_t_abs\": {:.6},\n",
            result.welch_t_abs
        ));
        output.push_str(&format!("      \"threshold\": {:.6},\n", result.threshold));
        output.push_str("      \"passed\": ");
        output.push_str(if result.passed { "true\n" } else { "false\n" });
        output.push_str("    }");
        if index + 1 != results.len() {
            output.push(',');
        }
        output.push('\n');
    }
    output.push_str("  ]\n");
    output.push_str("}\n");
    output
}

fn generated_at_utc() -> String {
    command_output("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"])
}

fn rustc_host_target() -> String {
    command_output("rustc", &["-vV"])
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap_or("unknown")
        .to_owned()
}

fn cpu_description() -> String {
    if let Ok(value) = env::var("PROCESSOR_IDENTIFIER") {
        return value;
    }
    if env::consts::OS == "macos" {
        let value = command_output("sysctl", &["-n", "machdep.cpu.brand_string"]);
        if !value.starts_with("unavailable:") && !value.is_empty() {
            return value;
        }
    }
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                matches!(key.trim(), "model name" | "Hardware" | "Processor")
                    .then(|| value.trim().to_owned())
            })
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

fn environment_value(name: &str, fallback: &str) -> String {
    env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

fn workflow_run_url() -> String {
    match (
        env::var("GITHUB_SERVER_URL"),
        env::var("GITHUB_REPOSITORY"),
        env::var("GITHUB_RUN_ID"),
    ) {
        (Ok(server), Ok(repository), Ok(run_id)) => {
            format!("{server}/{repository}/actions/runs/{run_id}")
        }
        _ => "local".to_owned(),
    }
}

fn push_json_field(output: &mut String, key: &str, value: &str, comma: bool, indent: usize) {
    output.push_str(&" ".repeat(indent));
    output.push('"');
    output.push_str(key);
    output.push_str("\": ");
    output.push('"');
    output.push_str(&json_escape(value));
    output.push('"');
    if comma {
        output.push(',');
    }
    output.push('\n');
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other if other.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", other as u32));
            }
            other => escaped.push(other),
        }
    }
    escaped
}

fn command_output(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        Ok(output) => String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        Err(error) => format!("unavailable: {error}"),
    }
}

fn enabled_features() -> String {
    let mut features = Vec::new();
    if cfg!(feature = "asm-compare") {
        features.push("asm-compare");
    }
    if cfg!(feature = "strict-compare") {
        features.push("strict-compare");
    }
    if features.is_empty() {
        "portable-fallback".to_owned()
    } else {
        features.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_accepts_pasted_unicode_spacing() {
        let config = parse_args_from([
            "--seed",
            "12345",
            "\u{00a0}\u{00a0}--samples",
            "\u{00a0}10\u{00a0}",
            "\u{00a0}--inner",
            "2",
            "\u{00a0}--warmup",
            "3",
            "\u{00a0}--threshold",
            "9.5",
            "\u{00a0}--output",
            "target/ct-leakage.json\u{00a0}",
        ])
        .expect("unicode-spaced arguments should parse");

        assert_eq!(config.seed, Some(12_345));
        assert_eq!(config.samples, 10);
        assert_eq!(config.inner, 2);
        assert_eq!(config.warmup, 3);
        assert_eq!(config.threshold, 9.5);
        assert_eq!(config.output.as_deref(), Some("target/ct-leakage.json"));
    }

    #[test]
    fn write_report_creates_parent_directories() {
        let base = std::env::temp_dir().join(format!(
            "ct-leakage-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos()
        ));
        let output = base.join("target").join("ct-leakage.json");

        write_report(
            output
                .to_str()
                .expect("temporary path should be valid UTF-8"),
            "{}\n",
        )
        .expect("nested output path should be created");

        let written = fs::read_to_string(&output).expect("report should be readable");
        assert_eq!(written, "{}\n");

        fs::remove_dir_all(base).expect("temporary directory should be removable");
    }

    #[test]
    fn class_schedule_is_balanced_and_shuffled() {
        let mut rng = XorShift64::new(0x243F_6A88_85A3_08D3);
        let schedule = balanced_class_schedule(50_000, &mut rng);
        let count_a = schedule
            .iter()
            .filter(|class| matches!(class, Class::A))
            .count();
        let count_b = schedule.len() - count_a;

        assert_eq!(count_a, 25_000);
        assert_eq!(count_b, 25_000);
        assert!(schedule[..128].iter().any(|class| matches!(class, Class::A)));
        assert!(schedule[..128].iter().any(|class| matches!(class, Class::B)));
        assert!(schedule[49_872..]
            .iter()
            .any(|class| matches!(class, Class::A)));
        assert!(schedule[49_872..]
            .iter()
            .any(|class| matches!(class, Class::B)));
    }

    #[test]
    fn odd_class_schedule_differs_by_one_sample() {
        let mut rng = XorShift64::new(7);
        let schedule = balanced_class_schedule(11, &mut rng);
        let count_a = schedule
            .iter()
            .filter(|class| matches!(class, Class::A))
            .count();

        assert_eq!(count_a, 5);
        assert_eq!(schedule.len() - count_a, 6);
    }
}
