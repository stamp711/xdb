use std::collections::HashMap;

use super::constants::DW_FORM_implicit_const;
use super::cursor::Cursor;

#[derive(Clone, Debug)]
pub struct AttrSpec {
    pub attr: u64,
    pub form: u64,
    pub implicit_const: i64,
}

#[derive(Clone, Debug)]
pub struct Abbrev {
    pub code: u64,
    pub tag: u64,
    pub has_children: bool,
    pub attrs: Vec<AttrSpec>,
}

/// Abbreviation codes are almost always a dense run starting at 1, so the
/// common case is indexed directly; anything out of order spills to a map.
#[derive(Default)]
pub struct AbbrevTable {
    dense: Vec<Abbrev>,
    sparse: HashMap<u64, Abbrev>,
}

impl AbbrevTable {
    pub fn parse(section: &[u8], offset: usize) -> Self {
        let mut cursor = Cursor::at(section, offset);
        let mut table = AbbrevTable::default();

        loop {
            let code = cursor.uleb128();
            if code == 0 {
                break;
            }
            let tag = cursor.uleb128();
            let has_children = cursor.u8() != 0;

            let mut attrs = Vec::new();
            loop {
                let attr = cursor.uleb128();
                let form = cursor.uleb128();
                if attr == 0 && form == 0 {
                    break;
                }
                let implicit_const = if form == DW_FORM_implicit_const {
                    cursor.sleb128()
                } else {
                    0
                };
                attrs.push(AttrSpec {
                    attr,
                    form,
                    implicit_const,
                });
            }

            table.insert(Abbrev {
                code,
                tag,
                has_children,
                attrs,
            });
        }

        table
    }

    fn insert(&mut self, abbrev: Abbrev) {
        if abbrev.code == self.dense.len() as u64 + 1 {
            self.dense.push(abbrev);
        } else {
            self.sparse.insert(abbrev.code, abbrev);
        }
    }

    pub fn get(&self, code: u64) -> Option<&Abbrev> {
        let index = code.checked_sub(1)? as usize;
        if index < self.dense.len() {
            Some(&self.dense[index])
        } else {
            self.sparse.get(&code)
        }
    }
}
