use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const ODIN_REVISION: &str = "84bc3fc";

fn main() {
    println!("cargo:rerun-if-changed=odin");
    println!("cargo:rerun-if-env-changed=ODIN");
    let compiler = env::var_os("ODIN").unwrap_or_else(|| OsString::from("odin"));
    let version = Command::new(&compiler)
        .arg("version")
        .output()
        .expect("Odin is required; install dev-2026-10 or set ODIN to its executable");
    assert!(
        version.status.success()
            && String::from_utf8_lossy(&version.stdout).contains("version dev-2026-10")
            && String::from_utf8_lossy(&version.stdout).contains(&format!(":{ODIN_REVISION}")),
        "marmot-markdown requires Odin {ODIN_REVISION}; found {}",
        String::from_utf8_lossy(&version.stdout).trim()
    );

    let target = env::var("TARGET").expect("Cargo TARGET");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo target architecture");
    let os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo target OS");
    let arch = match arch.as_str() {
        "x86_64" => "amd64",
        "x86" => "i386",
        "aarch64" => "arm64",
        "arm" => "arm32",
        _ => panic!("unsupported Odin target architecture: {target}"),
    };
    let odin_os = match os.as_str() {
        "macos" | "ios" => "darwin",
        "android" | "linux" => "linux",
        "windows" => "windows",
        "freebsd" => "freebsd",
        "netbsd" => "netbsd",
        "openbsd" => "openbsd",
        _ => panic!("unsupported Odin target OS: {target}"),
    };
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let archive = out_dir.join(if os == "windows" {
        "marmot_markdown_odin.lib"
    } else {
        "libmarmot_markdown_odin.a"
    });
    // Always regenerate the archive when Cargo runs this build script. A clean
    // crate build must include native compilation, not reuse an external cache.
    if archive.exists() {
        fs::remove_file(&archive).expect("remove previous Odin archive");
    }
    let object_output = os == "android" || os == "ios";
    let parallel_codegen =
        target == "x86_64-unknown-linux-gnu" && env::var("OPT_LEVEL").as_deref() != Ok("0");
    let native_output = if parallel_codegen {
        let directory = out_dir.join("llvm");
        fs::create_dir_all(&directory).expect("create native LLVM output directory");
        directory
    } else if object_output {
        out_dir.join("marmot_markdown_odin.o")
    } else {
        archive.clone()
    };
    let mut command = Command::new(compiler);
    command
        .args(["build", "odin", "-no-entry-point", "-bedrock"])
        .arg(if parallel_codegen {
            "-build-mode:llvm-ir"
        } else if object_output {
            "-build-mode:obj"
        } else {
            "-build-mode:lib"
        })
        .arg(format!("-target:{odin_os}_{arch}"))
        .arg(format!("-out:{}", native_output.display()))
        .arg("-reloc-mode:pic")
        .arg("-use-single-module")
        .arg("-thread-count:8")
        .arg("-warnings-as-errors")
        .arg(
            if parallel_codegen || env::var("OPT_LEVEL").as_deref() == Ok("0") {
                "-o:minimal"
            } else {
                "-o:speed"
            },
        );
    if os == "windows" {
        command.arg("-linker:msvc");
    }
    if os == "ios" {
        command.arg(if target.ends_with("-sim") || arch == "amd64" {
            "-subtarget:iphonesimulator"
        } else {
            "-subtarget:iphone"
        });
        println!("cargo:rerun-if-env-changed=IPHONEOS_DEPLOYMENT_TARGET");
        if let Ok(minimum) = env::var("IPHONEOS_DEPLOYMENT_TARGET") {
            command.arg(format!("-minimum-os-version:{minimum}"));
        }
    }
    let archiver = if os == "android" {
        let (ndk, toolchain, archiver) = android_toolchain(&target);
        println!("cargo:rerun-if-env-changed=ANDROID_API");
        let api = env::var("ANDROID_API").unwrap_or_else(|_| "26".into());
        command
            .arg("-subtarget:android")
            .arg(format!("-minimum-os-version:{api}"))
            .env("ODIN_ANDROID_NDK", ndk)
            .env("ODIN_ANDROID_NDK_TOOLCHAIN", toolchain);
        Some(Command::new(archiver))
    } else if os == "ios" {
        Some(Command::new("ar"))
    } else {
        None
    };
    if os == "macos" {
        println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
        if let Ok(minimum) = env::var("MACOSX_DEPLOYMENT_TARGET") {
            command.arg(format!("-minimum-os-version:{minimum}"));
        }
    }
    let status = command.status().expect("run pinned Odin compiler");
    assert!(
        status.success(),
        "Odin parser compilation failed for {target}"
    );
    if parallel_codegen {
        finalize_native(&native_output, &archive);
    } else if let Some(mut archiver) = archiver {
        let status = archiver
            .arg("crs")
            .arg(&archive)
            .arg(&native_output)
            .status()
            .expect("run native object archiver");
        assert!(status.success(), "archive Odin object for {target}");
    }
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=marmot_markdown_odin");
    if os != "windows" {
        println!("cargo:rustc-link-lib=m");
    }
}

fn finalize_native(directory: &Path, archive: &Path) {
    let rustc = env::var_os("RUSTC").expect("Cargo RUSTC");
    let sysroot = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .expect("find Rust sysroot");
    assert!(sysroot.status.success(), "find Rust sysroot");
    let sysroot = String::from_utf8(sysroot.stdout).expect("UTF-8 Rust sysroot");
    let tools = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(env::var("HOST").expect("Cargo HOST"))
        .join("bin");
    let suffix = env::consts::EXE_SUFFIX;
    let combine = "instcombine<max-iterations=1;no-verify-fixpoint>";
    // Bounded scalar cleanup plus inlining; ELF LTO partitions only machine-code
    // generation. The archive contains native objects before rustc consumes it.
    let passes = format!(
        "function(sroa,early-cse,{combine},simplifycfg),cgscc(function-attrs),\
         inliner-wrapper,cgscc(function-attrs),function(sroa,early-cse,{combine},\
         simplifycfg,sccp,correlated-propagation,jump-threading,{combine},\
         simplifycfg,memcpyopt,dse,adce),globaldce"
    );
    run_native(
        Command::new(tools.join(format!("opt{suffix}")))
            .arg(format!("-passes={passes}"))
            .arg(directory.join(".ll"))
            .arg("-o")
            .arg(directory.join("optimized.bc")),
    );
    run_native(
        Command::new(tools.join(format!("rust-lld{suffix}")))
            .args([
                "-flavor",
                "gnu",
                "-r",
                "--lto-O0",
                "--lto-CGO1",
                "--lto-partitions=16",
            ])
            .arg("-o")
            .arg(directory.join("markdown.o"))
            .arg(directory.join("optimized.bc")),
    );
    run_native(
        Command::new(tools.join(format!("llvm-ar{suffix}")))
            .arg("crs")
            .arg(archive)
            .arg(directory.join("markdown.o")),
    );
}

fn run_native(command: &mut Command) {
    let status = command
        .status()
        .expect("run pinned native backend; install llvm-tools-preview");
    assert!(
        status.success(),
        "native Markdown backend failed: {command:?}"
    );
}

fn android_toolchain(target: &str) -> (PathBuf, PathBuf, PathBuf) {
    let ar_key = format!("AR_{}", target.replace('-', "_"));
    let cargo_ar = format!(
        "CARGO_TARGET_{}_AR",
        target.replace('-', "_").to_uppercase()
    );
    let keys = [
        "ODIN_ANDROID_NDK",
        "ODIN_ANDROID_NDK_TOOLCHAIN",
        "ANDROID_NDK_HOME",
        "ANDROID_NDK_ROOT",
        "NDK_HOME",
        ar_key.as_str(),
        cargo_ar.as_str(),
    ];
    for key in keys {
        println!("cargo:rerun-if-env-changed={key}");
    }
    // kotlin-bindings.sh exports the selected NDK archiver even when its NDK
    // root came from SDK discovery rather than an explicit environment variable.
    let configured_ar = env::var_os(&ar_key)
        .or_else(|| env::var_os(&cargo_ar))
        .map(PathBuf::from);
    let configured_toolchain = env::var_os("ODIN_ANDROID_NDK_TOOLCHAIN")
        .map(PathBuf::from)
        .or_else(|| {
            configured_ar
                .as_ref()
                .and_then(|ar| ar.parent()?.parent().map(PathBuf::from))
        });
    let ndk = [
        "ODIN_ANDROID_NDK",
        "ANDROID_NDK_HOME",
        "ANDROID_NDK_ROOT",
        "NDK_HOME",
    ]
    .into_iter()
    .find_map(env::var_os)
    .map(PathBuf::from)
    .or_else(|| {
        configured_toolchain
            .as_ref()?
            .ancestors()
            .nth(4)
            .map(PathBuf::from)
    })
    .expect("Android builds require an NDK: set ANDROID_NDK_HOME or the target AR variable");
    let host = env::var("HOST").expect("Cargo HOST");
    let host_tag = if host.contains("apple") {
        "darwin-x86_64"
    } else if host.contains("windows") {
        "windows-x86_64"
    } else {
        "linux-x86_64"
    };
    let toolchain =
        configured_toolchain.unwrap_or_else(|| ndk.join("toolchains/llvm/prebuilt").join(host_tag));
    let archiver = configured_ar.unwrap_or_else(|| {
        toolchain.join("bin").join(if host.contains("windows") {
            "llvm-ar.exe"
        } else {
            "llvm-ar"
        })
    });
    assert!(
        archiver.is_file(),
        "Android NDK archiver missing: {}",
        archiver.display()
    );
    (ndk, toolchain, archiver)
}
