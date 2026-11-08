//! End-to-end parser measurement. Corpus preparation and output are untimed;
//! public parse, AST allocation/conversion, black-box consumption and drop are timed.
use std::{hint::black_box, time::Instant};

struct Case {
    id: &'static str,
    source: String,
}

fn corpus() -> Vec<Case> {
    let mut cases = Vec::new();
    macro_rules! golden {
        ($name:literal) => {
            cases.push(Case {
                id: concat!("golden/", $name),
                source: include_str!(concat!("../tests/golden/", $name, ".md")).to_owned(),
            });
        };
    }
    golden!("bare_urls");
    golden!("details");
    golden!("kitchen_sink");
    golden!("nested_containers");
    golden!("nostr_heavy");
    golden!("tables_and_math");
    cases.push(Case {
        id: "chat/plain",
        source: "Hey! Are we still meeting at 18:30?\n\nYes, see you by the station. Bring a jacket; it looks like rain.\n".into(),
    });
    cases.push(Case {
        id: "chat/unicode",
        source: "こんにちは、世界 🌍! **مرحبا بالعالم** — café, naïve, e\u{301}.\n\n> Привет 👩🏽‍💻\n\n[日本語](https://example.org/東京) and `λ → ∑`\n".repeat(8),
    });
    let mixed = include_str!("../tests/golden/kitchen_sink.md").to_owned()
        + "\n"
        + include_str!("../tests/golden/details.md")
        + "\n"
        + include_str!("../tests/golden/tables_and_math.md")
        + "\n";
    cases.push(Case {
        id: "document/mixed-large",
        source: mixed.repeat(64),
    });
    cases.push(Case {
        id: "adversarial/delimiters",
        source: "*_~`[![a]((\\*___~~`` unmatched ".repeat(512),
    });
    cases.push(Case {
        id: "adversarial/details",
        source: "<details>\n<summary>open **summary**</summary>\n\n".repeat(48)
            + &"body <summary>stray</summary> &amp; text\n".repeat(32)
            + &"\n</details>\n".repeat(48)
            + &"\n<details><summary>never closed\n".repeat(64),
    });
    let row = format!(
        "| {} |\n",
        vec!["cell **x** \\| [y](https://example.org)"; 24].join(" | ")
    );
    let separator = format!("| {} |\n", vec![":---:"; 24].join(" | "));
    cases.push(Case {
        id: "adversarial/table",
        source: row.clone() + &separator + &row.repeat(96) + "| malformed | row |\n",
    });
    cases.push(Case {
        id: "adversarial/depth",
        source: (1..=96)
            .map(|depth| format!("{}level {depth} **value**\n", "> ".repeat(depth)))
            .collect::<String>()
            + "\n"
            + &(0..96)
                .map(|depth| format!("{}- item {depth}\n", "  ".repeat(depth)))
                .collect::<String>(),
    });
    cases
}

fn fingerprint(source: &str) -> u64 {
    source.bytes().fold(0xcbf29ce484222325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    })
}

fn measure(case: &Case, iterations: u64) -> u128 {
    let started = Instant::now();
    for _ in 0..iterations {
        let document = marmot_markdown::parse(black_box(case.source.as_str()));
        drop(black_box(document));
    }
    started.elapsed().as_nanos()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cases = corpus();
    if args.as_slice() == ["--list"] {
        for case in &cases {
            println!(
                "{{\"case\":\"{}\",\"bytes\":{},\"fnv1a64\":\"{:016x}\"}}",
                case.id,
                case.source.len(),
                fingerprint(&case.source)
            );
        }
        return;
    }
    assert!(
        args.len() == 4
            && args[0] == "--case"
            && (args[2] == "--iterations" || args[2] == "--calibrate-ms"),
        "Usage: measure --list | --case ID (--iterations N | --calibrate-ms N)"
    );
    let case = cases
        .iter()
        .find(|case| case.id == args[1])
        .expect("unknown case");
    let count: u64 = args[3].parse().expect("positive integer");
    assert!(count > 0);
    // Warm instruction/data paths before every sample, outside its timer.
    measure(case, 8);
    let (iterations, elapsed_ns) = if args[2] == "--calibrate-ms" {
        let target_ns = u128::from(count) * 1_000_000;
        let mut iterations = 1_u64;
        loop {
            let elapsed = measure(case, iterations);
            if elapsed >= target_ns {
                break (iterations, elapsed);
            }
            iterations = iterations.checked_mul(2).expect("calibration overflow");
        }
    } else {
        (count, measure(case, count))
    };
    println!(
        "{{\"case\":\"{}\",\"bytes\":{},\"fnv1a64\":\"{:016x}\",\"iterations\":{},\"elapsed_ns\":{},\"ns_per_parse\":{:.6}}}",
        case.id,
        case.source.len(),
        fingerprint(&case.source),
        iterations,
        elapsed_ns,
        elapsed_ns as f64 / iterations as f64
    );
}
