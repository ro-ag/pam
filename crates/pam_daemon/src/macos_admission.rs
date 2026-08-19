use std::{
    io::Read as _,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use pam_model::{
    RuntimeError, RuntimeHostAdmission, RuntimeHostSnapshot, RuntimeMemoryPressure,
    RuntimeSwapTrend,
};

const SYSCTL_PATH: &str = "/usr/sbin/sysctl";
const VM_STAT_PATH: &str = "/usr/bin/vm_stat";
const MAX_SYSCTL_OUTPUT_BYTES: usize = 256;
const MAX_VM_STAT_OUTPUT_BYTES: usize = 16 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const SWAP_TREND_INTERVAL: Duration = Duration::from_millis(250);
const GIB: u64 = 1024 * 1024 * 1024;
const MIN_OS_RESERVE_BYTES: u64 = 8 * GIB;
const PAM_APPLICATION_RESERVE_BYTES: u64 = GIB;
const PROJECTION_CONTINGENCY_BYTES: u64 = GIB;

#[derive(Debug, Default)]
pub(crate) struct MacosRuntimeHostAdmission;

impl RuntimeHostAdmission for MacosRuntimeHostAdmission {
    fn snapshot(&self) -> Result<RuntimeHostSnapshot, RuntimeError> {
        let first_swapouts = sample_swapouts()?;
        thread::sleep(SWAP_TREND_INTERVAL);
        let second_swapouts = sample_swapouts()?;
        let swap_trend = swap_trend_from_samples(first_swapouts, second_swapouts);
        let bytes = run_bounded_command(
            SYSCTL_PATH,
            &[
                "-n",
                "hw.memsize",
                "kern.memorystatus_level",
                "kern.memorystatus_vm_pressure_level",
            ],
            MAX_SYSCTL_OUTPUT_BYTES,
        )?;
        parse_snapshot(&bytes, swap_trend)
    }
}

fn run_bounded_command(
    path: &str,
    arguments: &[&str],
    max_output_bytes: usize,
) -> Result<Vec<u8>, RuntimeError> {
    let mut child = Command::new(path)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| RuntimeError::AdmissionUnavailable("host admission query failed"))?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => {
                return Err(RuntimeError::AdmissionUnavailable(
                    "host admission query failed",
                ));
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RuntimeError::AdmissionUnavailable(
                    "host admission query timed out",
                ));
            }
        }
    }
    let stdout = child.stdout.take().ok_or_else(invalid_snapshot)?;
    let mut bytes = Vec::with_capacity(max_output_bytes);
    stdout
        .take(u64::try_from(max_output_bytes.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| invalid_snapshot())?;
    Ok(bytes)
}

fn sample_swapouts() -> Result<u64, RuntimeError> {
    let bytes = run_bounded_command(VM_STAT_PATH, &[], MAX_VM_STAT_OUTPUT_BYTES)?;
    parse_swapouts(&bytes)
}

pub(super) fn parse_swapouts(bytes: &[u8]) -> Result<u64, RuntimeError> {
    if bytes.is_empty() || bytes.len() > MAX_VM_STAT_OUTPUT_BYTES || !bytes.is_ascii() {
        return Err(invalid_snapshot());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_snapshot())?;
    let mut matches = text
        .lines()
        .filter_map(|line| line.strip_prefix("Swapouts:"));
    let value = matches.next().ok_or_else(invalid_snapshot)?.trim();
    if matches.next().is_some() {
        return Err(invalid_snapshot());
    }
    let digits = value.strip_suffix('.').ok_or_else(invalid_snapshot)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_snapshot());
    }
    digits.parse().map_err(|_| invalid_snapshot())
}

pub(super) const fn swap_trend_from_samples(first: u64, second: u64) -> RuntimeSwapTrend {
    if second == first {
        RuntimeSwapTrend::Stable
    } else if second > first {
        RuntimeSwapTrend::Rising
    } else {
        RuntimeSwapTrend::Unknown
    }
}

pub(super) fn parse_snapshot(
    bytes: &[u8],
    swap_trend: RuntimeSwapTrend,
) -> Result<RuntimeHostSnapshot, RuntimeError> {
    if bytes.is_empty() || bytes.len() > MAX_SYSCTL_OUTPUT_BYTES || !bytes.is_ascii() {
        return Err(invalid_snapshot());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_snapshot())?;
    let mut fields = text.split_ascii_whitespace();
    let total_bytes = parse_u64(fields.next())?;
    let available_percent = parse_u64(fields.next())?;
    let pressure_level = parse_u64(fields.next())?;
    if fields.next().is_some() || total_bytes == 0 || available_percent > 100 {
        return Err(invalid_snapshot());
    }
    let available_bytes = u64::try_from(
        u128::from(total_bytes)
            .checked_mul(u128::from(available_percent))
            .ok_or_else(invalid_snapshot)?
            / 100,
    )
    .map_err(|_| invalid_snapshot())?;
    let twenty_percent = total_bytes / 5 + u64::from(!total_bytes.is_multiple_of(5));
    let reserved_os_bytes = MIN_OS_RESERVE_BYTES.max(twenty_percent);
    let pressure = match pressure_level {
        1 => RuntimeMemoryPressure::Normal,
        2 => RuntimeMemoryPressure::Warning,
        4 => RuntimeMemoryPressure::Critical,
        _ => RuntimeMemoryPressure::Unknown,
    };
    RuntimeHostSnapshot::new(
        total_bytes,
        available_bytes,
        reserved_os_bytes,
        PAM_APPLICATION_RESERVE_BYTES,
        PROJECTION_CONTINGENCY_BYTES,
        pressure,
        swap_trend,
    )
}

fn parse_u64(value: Option<&str>) -> Result<u64, RuntimeError> {
    let value = value.ok_or_else(invalid_snapshot)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_snapshot());
    }
    value.parse().map_err(|_| invalid_snapshot())
}

fn invalid_snapshot() -> RuntimeError {
    RuntimeError::AdmissionUnavailable("host memory query returned invalid data")
}
