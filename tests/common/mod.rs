#![allow(dead_code)]

use std::path::PathBuf;

use nix::sys::signal::kill;
use nix::unistd::Pid;

pub fn target_path(name: &str) -> PathBuf {
    PathBuf::from(env!("XDB_TEST_TARGETS")).join(name)
}

pub fn process_exists(pid: Pid) -> bool {
    kill(pid, None).is_ok()
}

pub fn process_status(pid: Pid) -> char {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let after_comm = stat.rsplit_once(')').unwrap().1;
    after_comm.trim_start().chars().next().unwrap()
}
