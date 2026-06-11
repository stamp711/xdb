mod common;

use common::{entry_point_offset, load_address, target_path};
use nix::sys::signal::Signal;
use xdb::{Pipe, Process, ProcessState, Stoppoint, VirtAddr};

#[test]
fn create_site() {
    let mut process = Process::launch(&target_path("run_endlessly"), true, None).unwrap();
    let id = process
        .create_breakpoint_site(VirtAddr(42), false, false)
        .unwrap();
    assert_eq!(
        process.breakpoint_sites().get_by_id(id).unwrap().address(),
        VirtAddr(42)
    );
}

#[test]
fn sites_have_unique_ids() {
    let mut process = Process::launch(&target_path("run_endlessly"), true, None).unwrap();
    let id1 = process
        .create_breakpoint_site(VirtAddr(42), false, false)
        .unwrap();
    let id2 = process
        .create_breakpoint_site(VirtAddr(43), false, false)
        .unwrap();
    let id3 = process
        .create_breakpoint_site(VirtAddr(44), false, false)
        .unwrap();
    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_ne!(id1, id3);
}

#[test]
fn site_lookup() {
    let mut process = Process::launch(&target_path("run_endlessly"), true, None).unwrap();
    let (va1, va2) = (VirtAddr(42), VirtAddr(43));
    let id1 = process.create_breakpoint_site(va1, false, false).unwrap();
    let id2 = process.create_breakpoint_site(va2, false, false).unwrap();

    let sites = process.breakpoint_sites();
    assert!(sites.contains_id(id1));
    assert!(sites.contains_address(va1));
    assert_eq!(sites.get_by_id(id1).unwrap().address(), va1);
    assert_eq!(sites.get_by_address(va2).unwrap().id(), id2);

    assert!(sites.get_by_address(VirtAddr(99)).is_err());
    assert!(sites.get_by_id(999).is_err());
}

#[test]
fn site_list_size() {
    let mut process = Process::launch(&target_path("run_endlessly"), true, None).unwrap();
    assert!(process.breakpoint_sites().is_empty());
    process
        .create_breakpoint_site(VirtAddr(42), false, false)
        .unwrap();
    process
        .create_breakpoint_site(VirtAddr(43), false, false)
        .unwrap();
    assert_eq!(process.breakpoint_sites().len(), 2);
}

#[test]
fn site_iteration() {
    let mut process = Process::launch(&target_path("run_endlessly"), true, None).unwrap();
    for addr in 42..42 + 99 {
        process
            .create_breakpoint_site(VirtAddr(addr), false, false)
            .unwrap();
    }
    for (i, site) in process.breakpoint_sites().iter().enumerate() {
        assert_eq!(site.address(), VirtAddr(42 + i as u64));
    }
}

#[test]
fn breakpoint_on_entry_point() {
    let mut channel = Pipe::new(false).unwrap();
    let hello = target_path("hello");
    let mut process = Process::launch(&hello, true, Some(channel.write_end().unwrap())).unwrap();
    channel.close_write();

    let entry_va = load_address(process.pid(), entry_point_offset(&hello));
    let id = process
        .create_breakpoint_site(entry_va, false, false)
        .unwrap();
    process.enable_breakpoint_site(id).unwrap();
    process.resume().unwrap();
    let reason = process.wait_on_signal().unwrap();

    assert_eq!(reason.state, ProcessState::Stopped);
    assert_eq!(reason.info, Signal::SIGTRAP as u8);
    assert_eq!(process.get_pc().unwrap(), entry_va);

    process.resume().unwrap();
    let reason = process.wait_on_signal().unwrap();
    assert_eq!(reason.state, ProcessState::Exited);
    assert_eq!(reason.info, 0);
    assert_eq!(channel.read().unwrap(), b"hello");
}

#[test]
fn remove_site() {
    let mut process = Process::launch(&target_path("end_immediately"), true, None).unwrap();
    let va = VirtAddr(0x42);

    let id = process.create_breakpoint_site(va, false, false).unwrap();
    assert_eq!(process.breakpoint_sites().len(), 1);
    process.remove_breakpoint_site_by_id(id).unwrap();
    assert!(process.breakpoint_sites().is_empty());

    process.create_breakpoint_site(va, false, false).unwrap();
    assert_eq!(process.breakpoint_sites().len(), 1);
    process.remove_breakpoint_site_by_address(va).unwrap();
    assert!(process.breakpoint_sites().is_empty());
}
