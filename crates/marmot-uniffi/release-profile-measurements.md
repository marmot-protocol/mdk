# MarmotKit release-profile measurements

Schema: 1
Source SHA: `f469eb912664fc274734bcbe150eaefe97e72949`
Builder SHA: `f469eb912664fc274734bcbe150eaefe97e72949`
Toolchains: rustc 1.97.1 (8bab26f4f 2026-07-14), cargo 1.97.1 (c980f4866 2026-06-30)
Features: `otlp-export,product-analytics-export` for the primary host comparison
Compared profiles: baseline `lto=false,codegen-units=16` vs candidate `lto=thin,codegen-units=1`
Strip: `none` for host/Apple, `symbols` for Android (both variants)

Byte counts below are the dated exact-head CI reports for
`f469eb912664fc274734bcbe150eaefe97e72949`. Object SHA-256 hashes were not
retained in those reports and are recorded as unavailable, never fabricated.

- Linux report sha256 `e0ddbd525e0b0b7a6cc210be510b78d422d5545e877fa17136a62683dc09438c`
- macOS report sha256 `16a485692a20cf406f0aba644666cadd457e9cb996c083df3ef27df984b616e8`

These are historical, pre-sanitization measurements, not acceptance evidence for
the current head. Fresh reports, artifact hashes, raw Criterion output and logs
are uploaded by the non-publishing **MarmotKit Release Profile** workflow.

Host and Android JNI libraries shrank in this combined-profile comparison.
It does not isolate the contribution of each setting. In particular, Cargo does
not apply cross-crate LTO to the mixed `cdylib/staticlib/lib` binding target;
the configured `lto=thin` value is not proof that the binding library received
LTO. It does apply to eligible executables, including the host binding generator.

The old Apple archives grew because members retained embedded LLVM bitcode.
Current builds disable new embedding only for native-archive invocations, then
use Rust's `llvm-objcopy` and Apple's `libtool` to remove residual toolchain
bitcode and rebuild the symbol index. Precompiled Rust 1.97.1
`compiler_builtins` members can contain bitcode independently of the workspace
LTO setting; deleting the sanitizer would not establish native-only archives.
Host binding generation retains its own compatible flags. Current acceptance
requires exact-head archive, binding-generation and Swift package validation.

| Target | Kind | Baseline bytes | Candidate bytes | Delta bytes | Delta % | Status |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| host | host_generation_library | 89634696 | 67334168 | -22300528 | -24.88 | measured |
| host | host_generation_library_default_features | unavailable | 66900488 | unavailable | unavailable | measured (candidate smoke) |
| aarch64-linux-android | android_jni_so | 52457072 | 40879280 | -11577792 | -22.07 | measured |
| armv7-linux-androideabi | android_jni_so | 35919768 | 29107768 | -6812000 | -18.96 | measured |
| i686-linux-android | android_jni_so | 64394492 | 50012508 | -14381984 | -22.33 | measured |
| x86_64-linux-android | android_jni_so | 59169416 | 47007320 | -12162096 | -20.55 | measured |
| aarch64-apple-ios | apple_static_archive | 178719288 | 331185520 | 152466232 | 85.31 | measured (pre-fix) |
| aarch64-apple-ios-sim | apple_static_archive | 177476856 | 330119400 | 152642544 | 86.01 | measured (pre-fix) |
| aarch64-apple-darwin | apple_static_archive | 178431872 | 330786824 | 152354952 | 85.39 | measured (pre-fix) |

## CPU (`group_lifecycle` / `create_group`, `--profile release`)

Dated exact-head Linux CI Criterion estimates. Candidate is slightly faster on
every collected row; there is no >5% regression to investigate.

| Benchmark | Baseline ns | Candidate ns | Delta % |
| --- | ---: | ---: | ---: |
| create_group/1 invitees, retention disabled | 4545186 | 4500168 | -0.99 |
| create_group/1 invitees, retention enabled | 4586158 | 4550598 | -0.78 |
| create_group/8 invitees, retention disabled | 10654347 | 10400413 | -2.38 |
| create_group/8 invitees, retention enabled | 10489065 | 10326795 | -1.55 |
| create_group/32 invitees, retention disabled | 32859615 | 31544648 | -4.00 |
| create_group/32 invitees, retention enabled | 32779736 | 30982631 | -5.48 |

The 32-invitee retention-enabled row is a 5.48% candidate speedup, not a
slowdown. No CPU investigation gate is open.

Host candidate library bytes: `67334168` (hash not retained in the dated report)
Host baseline library bytes: `89634696` (hash not retained in the dated report)
