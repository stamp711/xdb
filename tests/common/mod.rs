#![allow(dead_code)]

use std::path::PathBuf;

use nix::sys::signal::kill;
use nix::unistd::Pid;
use xdb::VirtAddr;

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

/// File offset of the ELF entry point, via `readelf` as an independent oracle.
pub fn entry_point_offset(path: &std::path::Path) -> u64 {
    let bytes = std::fs::read(path).unwrap();
    let entry = u64::from_le_bytes(bytes[24..32].try_into().unwrap());

    let output = std::process::Command::new("readelf")
        .args(["-WS"])
        .arg(path)
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    for line in text.lines() {
        // [N] .name PROGBITS <addr> <off> <size> ...
        let Some(rest) = line.split_once("PROGBITS") else {
            continue;
        };
        let cols: Vec<&str> = rest.1.split_whitespace().collect();
        let addr = u64::from_str_radix(cols[0], 16).unwrap();
        let off = u64::from_str_radix(cols[1], 16).unwrap();
        let size = u64::from_str_radix(cols[2], 16).unwrap();
        if entry >= addr && entry < addr + size {
            return entry - addr + off;
        }
    }
    panic!("could not find section containing entry point");
}

/// Runtime address of a file offset, via `/proc/<pid>/maps` first exec mapping.
pub fn load_address(pid: Pid, file_offset: u64) -> VirtAddr {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    for line in maps.lines() {
        // 5555..-5556.. r-xp 00001000 08:02 5280459 /path
        let cols: Vec<&str> = line.split_whitespace().collect();
        let perms = cols[1];
        if !perms.contains('x') {
            continue;
        }
        let start = u64::from_str_radix(cols[0].split('-').next().unwrap(), 16).unwrap();
        let map_offset = u64::from_str_radix(cols[2], 16).unwrap();
        return VirtAddr(start + (file_offset - map_offset));
    }
    panic!("could not find load address");
}
