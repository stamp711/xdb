use std::path::Path;
use std::{env, fs};

/// Test debuggees: real programs the debugger runs, compiled with debug info
/// and as PIE. The `cc` crate only builds static libraries, so the compiler is
/// driven directly to produce executables.
struct Target {
    name: &'static str,
    sources: &'static [&'static str],
    extra_flags: &'static [&'static str],
    is_asm: bool,
}

const TARGETS: &[Target] = &[
    Target {
        name: "run_endlessly",
        sources: &["run_endlessly.cpp"],
        extra_flags: &[],
        is_asm: false,
    },
    Target {
        name: "end_immediately",
        sources: &["end_immediately.cpp"],
        extra_flags: &[],
        is_asm: false,
    },
    Target {
        name: "hello",
        sources: &["hello.cpp"],
        extra_flags: &[],
        is_asm: false,
    },
    Target {
        name: "memory",
        sources: &["memory.cpp"],
        extra_flags: &[],
        is_asm: false,
    },
    Target {
        name: "anti_debugger",
        sources: &["anti_debugger.cpp"],
        extra_flags: &[],
        is_asm: false,
    },
    Target {
        name: "overloaded",
        sources: &["overloaded.cpp"],
        extra_flags: &[],
        is_asm: false,
    },
    Target {
        name: "step",
        sources: &["step.cpp"],
        extra_flags: &[],
        is_asm: false,
    },
    Target {
        name: "multi_cu",
        sources: &["multi_cu_main.cpp", "multi_cu_other.cpp"],
        extra_flags: &[],
        is_asm: false,
    },
    Target {
        name: "inlining",
        sources: &["inlining.cpp"],
        extra_flags: &[
            "-O3",
            "-fno-omit-frame-pointer",
            "-fno-optimize-sibling-calls",
        ],
        is_asm: false,
    },
    Target {
        name: "reg_write",
        sources: &["reg_write.s"],
        extra_flags: &[],
        is_asm: true,
    },
    Target {
        name: "reg_read",
        sources: &["reg_read.s"],
        extra_flags: &[],
        is_asm: true,
    },
];

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let src_dir = Path::new(&manifest_dir).join("tests/targets");
    let out_dir = Path::new(&env::var("OUT_DIR").unwrap()).join("targets");
    fs::create_dir_all(&out_dir).unwrap();

    let compiler = cc::Build::new().cpp(true).get_compiler();

    for target in TARGETS {
        let output = out_dir.join(target.name);

        let mut command = compiler.to_command();
        command.arg("-g");
        if !target.is_asm {
            command.args(["-O0", "-std=c++17"]);
        }
        command.arg("-pie").args(target.extra_flags);
        for source in target.sources {
            let path = src_dir.join(source);
            println!("cargo:rerun-if-changed={}", path.display());
            command.arg(&path);
        }
        command.arg("-o").arg(&output);

        let status = command
            .status()
            .unwrap_or_else(|e| panic!("failed to spawn compiler for {}: {e}", target.name));
        assert!(
            status.success(),
            "failed to build test target {}",
            target.name
        );
    }

    // Expose the directory so tests can locate the debuggees.
    println!("cargo:rustc-env=XDB_TEST_TARGETS={}", out_dir.display());
}
