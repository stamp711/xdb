use std::fs::{File, read_to_string};
use std::os::fd::AsFd;
use std::path::Path;

use nix::sys::signal::kill;
use nix::unistd::Pid;
use xdb::Process;

fn process_exists(pid: Pid) -> bool {
    kill(pid, None).is_ok()
}

fn get_process_status(pid: Pid) -> char {
    let stat = read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let after_comm = stat.rsplit_once(')').unwrap().1;
    after_comm.trim_start().chars().next().unwrap()
}

fn dev_null() -> File {
    File::options().write(true).open("/dev/null").unwrap()
}

#[test]
fn launch_succeeds() {
    let process = Process::launch(Path::new("yes"), true, None).unwrap();
    assert!(process_exists(process.pid()));
}

#[test]
fn launch_no_such_program_fails() {
    let result = Process::launch(Path::new("you_do_not_have_to_be_good"), true, None);
    assert!(result.is_err());
}

#[test]
fn attach_succeeds() {
    let null = dev_null();
    let target = Process::launch(Path::new("yes"), false, Some(null.as_fd())).unwrap();
    let _attached = Process::attach(target.pid()).unwrap();
    assert_eq!(get_process_status(target.pid()), 't');
}

#[test]
fn attach_invalid_pid_fails() {
    assert!(Process::attach(Pid::from_raw(0)).is_err());
}

#[test]
fn resume_succeeds() {
    let null = dev_null();
    let mut process = Process::launch(Path::new("yes"), true, Some(null.as_fd())).unwrap();
    process.resume().unwrap();
    let status = get_process_status(process.pid());
    assert!(status == 'R' || status == 'S');
}

#[test]
fn resume_already_terminated_fails() {
    let mut process = Process::launch(Path::new("true"), true, None).unwrap();
    process.resume().unwrap();
    process.wait_on_signal().unwrap();
    assert!(process.resume().is_err());
}
