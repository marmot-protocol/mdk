const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The mdk module that consumers import.
    const mdk_mod = b.addModule("mdk", .{
        .root_source_file = b.path("src/mdk.zig"),
        .target = target,
        .optimize = optimize,
    });
    mdk_mod.addIncludePath(b.path("../mdk-cbindings/include"));

    // --- Tests ---------------------------------------------------------------

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/mdk.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addIncludePath(b.path("../mdk-cbindings/include"));

    // When running tests we need the actual Rust static library.
    // Build it first with: cargo build -p mdk-cbindings [--release]
    test_mod.addLibraryPath(b.path("../../target/debug"));
    test_mod.addLibraryPath(b.path("../../target/release"));
    test_mod.linkSystemLibrary("mdk", .{});
    test_mod.linkSystemLibrary("c", .{});

    const mod_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run mdk-zig unit tests");
    test_step.dependOn(&run_tests.step);
}
