#!/usr/bin/env bash
# Regenerate src/dwarf/constants.rs from the standard DWARF enumerations.
#
# The enums live in the C++ tree's verbatim copy of elfutils' dwarf.h. Pass its
# path as $1, or set DWARF_H; the default points at the sibling C++ checkout.
set -euo pipefail

src="${1:-${DWARF_H:-../../include/libxdb/detail/dwarf.h}}"
out="$(dirname "$0")/../src/dwarf/constants.rs"

{
    echo "//! DWARF constants extracted from the standard enumerations."
    echo "#![allow(non_upper_case_globals)]"
    echo
    # Constants: DW_PREFIX_name = 0xHEX or = DECIMAL. Dedup by name.
    {
        sed -nE 's/^[[:space:]]*(DW_[A-Z0-9]+_[A-Za-z0-9_]+)[[:space:]]*=[[:space:]]*(0x[0-9a-fA-F]+).*/pub const \1: u64 = \2;/p' "$src"
        sed -nE 's/^[[:space:]]*(DW_[A-Z0-9]+_[A-Za-z0-9_]+)[[:space:]]*=[[:space:]]*([0-9]+),?[[:space:]]*$/pub const \1: u64 = \2;/p' "$src"
    } | awk '!seen[$3]++'

    # Name-lookup functions for the dwarf_dump tool, deduped by value per category.
    for pair in TAG:tag_name AT:attr_name FORM:form_name; do
        prefix="${pair%%:*}"
        fn="${pair##*:}"
        echo
        echo "pub fn ${fn}(value: u64) -> Option<&'static str> {"
        echo "    match value {"
        sed -nE "s/^[[:space:]]*(DW_${prefix}_[A-Za-z0-9_]+)[[:space:]]*=[[:space:]]*(0x[0-9a-fA-F]+).*/        \2 => Some(\"\1\"),/p" "$src" | awk '!seen[$1]++'
        echo "        _ => None,"
        echo "    }"
        echo "}"
    done
} >"$out"

echo "wrote $out"
