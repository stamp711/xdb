#!/usr/bin/env bash
# Regenerate src/syscalls.rs from the x86-64 syscall list.
#
# The list lives in the C++ tree's DEFINE_SYSCALL(name, id) macro file. Pass its
# path as $1, or set SYSCALLS_DEF; the default points at the sibling C++ checkout.
set -euo pipefail

src="${1:-${SYSCALLS_DEF:-../../src/include/syscalls.def.hpp}}"
out="$(dirname "$0")/../src/syscalls.rs"

{
    echo "//! x86-64 Linux syscall number/name table."
    echo
    echo "macro_rules! syscalls {"
    echo '    ($(($name:literal, $id:literal)),* $(,)?) => {'
    echo "        pub fn syscall_id_to_name(id: u64) -> Option<&'static str> {"
    echo "            match id {"
    echo '                $($id => Some($name),)*'
    echo "                _ => None,"
    echo "            }"
    echo "        }"
    echo
    echo "        pub fn syscall_name_to_id(name: &str) -> Option<u64> {"
    echo "            match name {"
    echo '                $($name => Some($id),)*'
    echo "                _ => None,"
    echo "            }"
    echo "        }"
    echo "    };"
    echo "}"
    echo
    echo "syscalls! {"
    sed -nE 's/^DEFINE_SYSCALL\(([a-zA-Z0-9_]+), ([0-9]+)\)/    ("\1", \2),/p' "$src"
    echo "}"
    cat <<'RUST'

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_and_name_round_trip() {
        assert_eq!(syscall_id_to_name(0), Some("read"));
        assert_eq!(syscall_name_to_id("read"), Some(0));
        assert_eq!(syscall_id_to_name(16), Some("ioctl"));
        assert_eq!(syscall_name_to_id("ioctl"), Some(16));
        assert_eq!(syscall_id_to_name(99999), None);
    }
}
RUST
} >"$out"

echo "wrote $out"
