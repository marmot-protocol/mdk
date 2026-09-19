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

Host and Android JNI libraries shrank. Apple static archives grew about 85
percent on that head because Apple rustc defaults to `embed-bitcode=yes`, so
thin-LTO members carried native code plus LLVM bitcode, and the matching Rust
1.97.1 iOS `compiler_builtins` rlib retains a leftover `__LLVM,__bitcode`
section of size `0xe80`. macOS job `105104464502` then failed Validate Apple
archives on `compiler_builtins-*.rcgu.o`. This revision disables embed-bitcode
on Apple Cargo invocations and sanitizes leftover Mach-O bitcode sections
from every member without skipping names. Exact-head macOS CI on
`2c1fd5b97bd16c9577e18a795564579c2902f909` then failed sanitization because
relocatable `compiler_builtins` members keep `__LLVM,__bitcode` as a section
inside a parent `__TEXT` load command. The sanitizer now removes those
section-level leftovers; it still does not whitelist members. Exact-head macOS
CI on `e9fb5a8f577d2c6352d12eebf76111afbe8d6e01` then failed sanitization with
`unknown Mach-O load command 0x25 after mid-file bitcode removal`
(`LC_VERSION_MIN_IPHONEOS`). The sanitizer now keeps those offset-free
commands intact. Exact-head macOS CI on
`9dfab7008e1748a46df9b9240bb678fb4124d46c` then failed sanitization with
`segment offset 784 lands inside removed bitcode` because the parent
`__TEXT` `fileoff` equals the leftover bitcode start. The sanitizer now
snaps that segment onto the remaining native sections and still rejects
pointers that land strictly inside removed bitcode. Profile-affecting
MarmotKit sources and these dated bytes are unchanged except for that
sanitizer repair. Fresh exact-head CI is required after publication; these
dated numbers describe the pre-fix candidate.

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
