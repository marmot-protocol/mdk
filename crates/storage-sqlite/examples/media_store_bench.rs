//! Media file store benchmark (mdk#2314 step 0). Prints `MDK_BENCH` lines.
//!
//! Environment:
//! - `MDK_MEDIA_BENCH_DIR`: scratch directory (default: a new directory under
//!   the system temp directory). Needs room for the largest body about twice.
//! - `MDK_MEDIA_BENCH_SIZES`: comma-separated body sizes, with optional `K`/`M`
//!   suffixes (default `64K,1M,100M`).
//! - `MDK_MEDIA_BENCH_ITERATIONS`: repetitions per row (default 7; bodies of
//!   32 MiB or more use `MDK_MEDIA_BENCH_LARGE_ITERATIONS`, default 3).

use storage_sqlite::media_store_bench::{MediaStoreBenchConfig, run_media_store_benchmark};

fn parse_size(value: &str) -> usize {
    let value = value.trim();
    let (digits, scale) = match value.as_bytes().last() {
        Some(b'K' | b'k') => (&value[..value.len() - 1], 1024),
        Some(b'M' | b'm') => (&value[..value.len() - 1], 1024 * 1024),
        _ => (value, 1),
    };
    digits
        .parse::<usize>()
        .expect("invalid MDK_MEDIA_BENCH_SIZES entry")
        * scale
}

fn env_count(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .map(|value| value.parse().unwrap_or_else(|_| panic!("invalid {name}")))
}

fn main() {
    let mut config = MediaStoreBenchConfig::default();
    if let Ok(sizes) = std::env::var("MDK_MEDIA_BENCH_SIZES") {
        config.sizes = sizes.split(',').map(parse_size).collect();
    }
    if let Some(iterations) = env_count("MDK_MEDIA_BENCH_ITERATIONS") {
        config.iterations = iterations;
    }
    if let Some(iterations) = env_count("MDK_MEDIA_BENCH_LARGE_ITERATIONS") {
        config.large_iterations = iterations;
    }
    let (dir, _temp) = match std::env::var_os("MDK_MEDIA_BENCH_DIR") {
        Some(dir) => (dir.into(), None),
        None => {
            let temp = std::env::temp_dir().join(format!("mdk-media-bench-{}", std::process::id()));
            (temp.clone(), Some(RemoveOnDrop(temp)))
        }
    };
    run_media_store_benchmark(&dir, &config, &mut |line| println!("{line}"))
        .unwrap_or_else(|error| panic!("media store benchmark failed: {error}"));
}

struct RemoveOnDrop(std::path::PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
