mod common;

use std::path::PathBuf;

use common::target_path;
use nix::sys::signal::Signal;
use xdb::{ProcessState, Stoppoint, Target};

fn dev_null() -> std::fs::File {
    std::fs::File::options()
        .write(true)
        .open("/dev/null")
        .unwrap()
}

#[test]
fn source_level_breakpoints() {
    let null = dev_null();
    let mut target = Target::launch(
        &target_path("overloaded"),
        Some(std::os::fd::AsFd::as_fd(&null)),
    )
    .unwrap();

    let main_bp = target
        .create_line_breakpoint(PathBuf::from("overloaded.cpp"), 11, false, false)
        .unwrap();
    target.enable_breakpoint(main_bp).unwrap();

    target.resume().unwrap();
    target.wait_on_signal().unwrap();

    let entry = target.line_entry_at_pc().unwrap();
    assert_eq!(
        target.source_file_at_pc().unwrap().file_name().unwrap(),
        "overloaded.cpp"
    );
    assert_eq!(entry.line, 11);

    // Break on all three print_type overloads, then disable the lowest site.
    let print_bp = target
        .create_function_breakpoint("print_type".to_owned(), false, false)
        .unwrap();
    target.enable_breakpoint(print_bp).unwrap();

    let lowest = target
        .breakpoint(print_bp)
        .unwrap()
        .site_ids()
        .iter()
        .copied()
        .min_by_key(|&id| {
            target
                .process()
                .breakpoint_sites()
                .get_by_id(id)
                .unwrap()
                .address()
        })
        .unwrap();
    target
        .process_mut()
        .disable_breakpoint_site(lowest)
        .unwrap();

    target.resume().unwrap();
    target.wait_on_signal().unwrap();
    assert_eq!(target.line_entry_at_pc().unwrap().line, 6);

    target.resume().unwrap();
    target.wait_on_signal().unwrap();
    assert_eq!(target.line_entry_at_pc().unwrap().line, 8);

    target.resume().unwrap();
    let reason = target.wait_on_signal().unwrap();
    assert_eq!(reason.state, ProcessState::Exited);
}

#[test]
fn source_level_stepping() {
    let null = dev_null();
    let mut target =
        Target::launch(&target_path("step"), Some(std::os::fd::AsFd::as_fd(&null))).unwrap();

    let main_bp = target
        .create_function_breakpoint("main".to_owned(), false, false)
        .unwrap();
    target.enable_breakpoint(main_bp).unwrap();
    target.resume().unwrap();
    let reason = target.wait_on_signal().unwrap();
    assert_eq!(reason.info, Signal::SIGTRAP as u8);

    let pc = target.process().get_pc().unwrap();
    assert_eq!(target.function_name_at_address(pc), "main");

    target.step_over().unwrap();
    let new_pc = target.process().get_pc().unwrap();
    assert_ne!(new_pc, pc);
    assert_eq!(target.function_name_at_address(new_pc), "main");

    target.step_in().unwrap();
    let pc = target.process().get_pc().unwrap();
    assert_eq!(target.function_name_at_address(pc), "noinline");
    assert_eq!(target.stack().inline_height(), 2);

    target.step_in().unwrap();
    let new_pc = target.process().get_pc().unwrap();
    assert_eq!(new_pc, pc);
    assert_eq!(target.stack().inline_height(), 1);

    target.step_out().unwrap();
    let new_pc = target.process().get_pc().unwrap();
    assert_ne!(new_pc, pc);
    assert_eq!(target.function_name_at_address(pc), "noinline");

    target.step_out().unwrap();
    let pc = target.process().get_pc().unwrap();
    assert_eq!(target.function_name_at_address(pc), "main");
}
