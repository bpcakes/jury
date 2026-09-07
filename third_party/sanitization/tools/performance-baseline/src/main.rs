use sanitization::{wipe, SecretBytes, SecureSanitize};
use std::env;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MAX_WIPE_SCALING_RATIO: f64 = 128.0;
const MAX_SPECIALIZED_TO_GENERIC_RATIO: f64 = 0.50;
const MAX_SECRET_BYTES_TO_GENERIC_RATIO: f64 = 0.50;

struct Config {
    samples: usize,
    inner: usize,
    output: PathBuf,
}

fn main() {
    let config = parse_args().unwrap_or_else(|message| {
        eprintln!("{message}");
        eprintln!("usage: performance-baseline [--samples N] [--inner N] --output PATH");
        std::process::exit(2);
    });

    let mut wipe_64 = [0xA5u8; 64];
    let wipe_64_ns = median_ns(config.samples, config.inner, || {
        wipe_64[0] ^= 1;
        wipe::bytes(black_box(&mut wipe_64));
        black_box(wipe_64[0]);
    });

    let mut wipe_4096 = [0xA5u8; 4096];
    let wipe_4096_ns = median_ns(config.samples, config.inner, || {
        wipe_4096[0] ^= 1;
        wipe::bytes(black_box(&mut wipe_4096));
        black_box(wipe_4096[0]);
    });

    let mut generic_4096 = [0xA5u8; 4096];
    let generic_4096_ns = median_ns(config.samples, config.inner, || {
        generic_4096[0] ^= 1;
        black_box(&mut generic_4096).secure_sanitize();
        black_box(generic_4096[0]);
    });

    let mut secret_4096 = SecretBytes::<4096>::zeroed();
    let secret_4096_ns = median_ns(config.samples, config.inner, || {
        secret_4096.secure_clear();
        black_box(&secret_4096);
    });

    let wipe_scaling_ratio = ratio(wipe_4096_ns, wipe_64_ns);
    let specialized_to_generic_ratio = ratio(wipe_4096_ns, generic_4096_ns);
    let secret_bytes_to_generic_ratio = ratio(secret_4096_ns, generic_4096_ns);
    let passed = wipe_scaling_ratio <= MAX_WIPE_SCALING_RATIO
        && specialized_to_generic_ratio <= MAX_SPECIALIZED_TO_GENERIC_RATIO
        && secret_bytes_to_generic_ratio <= MAX_SECRET_BYTES_TO_GENERIC_RATIO;

    let report = format!(
        concat!(
            "{{\n",
            "  \"schema_version\": 1,\n",
            "  \"tool\": \"sanitization-performance-baseline\",\n",
            "  \"generated_at_unix\": {generated_at_unix},\n",
            "  \"git_commit\": \"{git_commit}\",\n",
            "  \"git_dirty\": {git_dirty},\n",
            "  \"target\": \"{target}\",\n",
            "  \"rustc\": \"{rustc}\",\n",
            "  \"runner\": \"{runner}\",\n",
            "  \"workflow_run\": \"{workflow_run}\",\n",
            "  \"passed\": {passed},\n",
            "  \"config\": {{ \"samples\": {samples}, \"inner\": {inner} }},\n",
            "  \"measurements_ns_per_operation\": {{\n",
            "    \"wipe_64\": {wipe_64_ns:.6},\n",
            "    \"wipe_4096\": {wipe_4096_ns:.6},\n",
            "    \"generic_array_4096\": {generic_4096_ns:.6},\n",
            "    \"secret_bytes_4096\": {secret_4096_ns:.6}\n",
            "  }},\n",
            "  \"ratios\": {{\n",
            "    \"wipe_scaling\": {wipe_scaling_ratio:.6},\n",
            "    \"specialized_to_generic\": {specialized_to_generic_ratio:.6},\n",
            "    \"secret_bytes_to_generic\": {secret_bytes_to_generic_ratio:.6}\n",
            "  }},\n",
            "  \"thresholds\": {{\n",
            "    \"max_wipe_scaling\": {max_wipe_scaling:.6},\n",
            "    \"max_specialized_to_generic\": {max_specialized_to_generic:.6},\n",
            "    \"max_secret_bytes_to_generic\": {max_secret_bytes_to_generic:.6}\n",
            "  }}\n",
            "}}\n"
        ),
        generated_at_unix = generated_at_unix(),
        git_commit = json_escape(&command_output("git", &["rev-parse", "HEAD"])),
        git_dirty = !command_output("git", &["status", "--short"]).is_empty(),
        target = json_escape(&rustc_host_target()),
        rustc = json_escape(&command_output("rustc", &["-vV"])),
        runner = json_escape(&env::var("RUNNER_NAME").unwrap_or_else(|_| "local".to_owned())),
        workflow_run = json_escape(&workflow_run_url()),
        passed = passed,
        samples = config.samples,
        inner = config.inner,
        wipe_64_ns = wipe_64_ns,
        wipe_4096_ns = wipe_4096_ns,
        generic_4096_ns = generic_4096_ns,
        secret_4096_ns = secret_4096_ns,
        wipe_scaling_ratio = wipe_scaling_ratio,
        specialized_to_generic_ratio = specialized_to_generic_ratio,
        secret_bytes_to_generic_ratio = secret_bytes_to_generic_ratio,
        max_wipe_scaling = MAX_WIPE_SCALING_RATIO,
        max_specialized_to_generic = MAX_SPECIALIZED_TO_GENERIC_RATIO,
        max_secret_bytes_to_generic = MAX_SECRET_BYTES_TO_GENERIC_RATIO,
    );

    write_report(&config.output, &report).unwrap_or_else(|error| {
        eprintln!("failed to write {}: {error}", config.output.display());
        std::process::exit(1);
    });
    println!(
        "performance baseline {} (structured report written to the requested output file)",
        if passed { "passed" } else { "failed" }
    );
    if !passed {
        std::process::exit(1);
    }
}

fn median_ns(samples: usize, inner: usize, mut body: impl FnMut()) -> f64 {
    for _ in 0..10 {
        body();
    }
    let mut values = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..inner {
            body();
        }
        values.push(start.elapsed().as_nanos() as f64 / inner as f64);
    }
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn ratio(numerator: f64, denominator: f64) -> f64 {
    if denominator == 0.0 {
        f64::INFINITY
    } else {
        numerator / denominator
    }
}

fn parse_args() -> Result<Config, String> {
    let mut samples = 31usize;
    let mut inner = 20usize;
    let mut output = None;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--samples" => samples = parse_usize("--samples", args.next())?,
            "--inner" => inner = parse_usize("--inner", args.next())?,
            "--output" => output = args.next().map(PathBuf::from),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if samples == 0 || inner == 0 {
        return Err("samples and inner must be non-zero".to_owned());
    }
    Ok(Config {
        samples,
        inner,
        output: output.ok_or_else(|| "--output requires a path".to_owned())?,
    })
}

fn parse_usize(flag: &str, value: Option<String>) -> Result<usize, String> {
    value
        .ok_or_else(|| format!("{flag} requires a value"))?
        .parse()
        .map_err(|_| format!("{flag} requires an integer"))
}

fn write_report(path: &Path, report: &str) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, report)
}

fn command_output(program: &str, arguments: &[&str]) -> String {
    match Command::new(program).args(arguments).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        Ok(output) => String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        Err(error) => format!("unavailable: {error}"),
    }
}

fn rustc_host_target() -> String {
    command_output("rustc", &["-vV"])
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap_or("unknown")
        .to_owned()
}

fn generated_at_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
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

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_rejects_zero_denominator() {
        assert!(ratio(1.0, 0.0).is_infinite());
    }

    #[test]
    fn json_escape_handles_report_metadata() {
        assert_eq!(json_escape("a\n\"b"), "a\\n\\\"b");
    }
}
