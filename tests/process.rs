mod common;

use common::{process_status, target_path};
use nix::unistd::Pid;
use xdb::Process;

#[test]
fn launch_succeeds() {
    let process = Process::launch(&target_path("run_endlessly"), true, None).unwrap();
    assert_eq!(process_status(process.pid()), 't');
}

#[test]
fn launch_no_such_program_fails() {
    let result = Process::launch(&target_path("you_do_not_have_to_be_good"), true, None);
    assert!(result.is_err());
}

#[test]
fn attach_succeeds() {
    let target = Process::launch(&target_path("run_endlessly"), false, None).unwrap();
    let _attached = Process::attach(target.pid()).unwrap();
    assert_eq!(process_status(target.pid()), 't');
}

#[test]
fn attach_invalid_pid_fails() {
    assert!(Process::attach(Pid::from_raw(0)).is_err());
}

#[test]
fn resume_succeeds() {
    let mut process = Process::launch(&target_path("run_endlessly"), true, None).unwrap();
    process.resume().unwrap();
    assert_eq!(process_status(process.pid()), 'R');
}

#[test]
fn resume_already_terminated_fails() {
    let mut process = Process::launch(&target_path("end_immediately"), true, None).unwrap();
    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert!(process.resume().is_err());
}
