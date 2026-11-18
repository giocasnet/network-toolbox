//! SNMP tables: from the walk of a branch to rows (one per index) and columns (one per object).

use super::client::VarBind;
use super::mib::{self, Kind};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize, PartialEq)]
pub struct Column {
    pub oid: String,
    pub name: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Row {
    /// Row index: the part of the OID after the column ("3", "192.0.2.1").
    pub index: String,
    pub cells: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Table {
    /// Table name (`IF-MIB::ifTable`) or the OID.
    pub name: String,
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
}

/// Where to start to read the table given by `oid`: a table by name (`ifTable`) is read
/// whole, for a column (`ifDescr`) the table containing it is read, an OID without a
/// name is read as it is.
pub fn root(oid: &[u32]) -> Vec<u32> {
    match mib::object(oid) {
        Some((o, len)) if o.kind == Kind::Column => oid[..len - 2].to_vec(),
        _ => oid.to_vec(),
    }
}

/// OID of the row (`<table>.1`) inside the branch read. With the built-in names it is
/// known; without, the shape common to all SNMP tables applies: if every value is under
/// `<branch>.1` the branch is the table, otherwise it already is the row.
fn entry(root: &[u32], vbs: &[VarBind]) -> Vec<u32> {
    let under_one = vbs
        .iter()
        .all(|v| v.oid.len() > root.len() + 2 && v.oid[root.len()] == 1);
    let table = match mib::object(root) {
        Some((o, len)) if len == root.len() => o.kind == Kind::Table,
        _ => under_one,
    };
    let mut e = root.to_vec();
    if table {
        e.push(1);
    }
    e
}

/// Rows and columns from the values read under `root`. `None` if they do not have the
/// shape of a table (no values, or values without column and index).
pub fn build(root: &[u32], vbs: &[VarBind]) -> Option<Table> {
    let e = entry(root, vbs);
    let mut columns: Vec<u32> = Vec::new();
    // index -> (column -> cell); BTreeMap = rows in index order
    let mut rows: BTreeMap<&[u32], BTreeMap<u32, String>> = BTreeMap::new();
    for vb in vbs {
        if !vb.oid.starts_with(&e) || vb.oid.len() < e.len() + 2 {
            continue;
        }
        let col = vb.oid[e.len()];
        if !columns.contains(&col) {
            columns.push(col);
        }
        rows.entry(&vb.oid[e.len() + 1..])
            .or_default()
            .insert(col, mib::cell(&vb.oid, &vb.value));
    }
    if rows.is_empty() {
        return None;
    }
    columns.sort_unstable();
    let col_oid = |c: u32| {
        let mut o = e.clone();
        o.push(c);
        o
    };
    Some(Table {
        name: mib::name(root),
        columns: columns
            .iter()
            .map(|c| {
                let o = col_oid(*c);
                Column {
                    name: mib::short_name(&o),
                    oid: mib::dotted(&o),
                }
            })
            .collect(),
        rows: rows
            .into_iter()
            .map(|(index, cells)| Row {
                index: mib::dotted(index),
                cells: columns
                    .iter()
                    .map(|c| cells.get(c).cloned().unwrap_or_default())
                    .collect(),
            })
            .collect(),
    })
}

/// CSV of the table: `;` separator (the one Excel opens by itself in Italian locales),
/// fields with `;`, quotes or newlines are quoted.
pub fn csv(t: &Table) -> String {
    let field = |s: &str| {
        if s.contains([';', '"', '\n', '\r']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    };
    let mut out = vec![std::iter::once(crate::t!("Indice", "Index").to_string())
        .chain(t.columns.iter().map(|c| field(&c.name)))
        .collect::<Vec<_>>()
        .join(";")];
    for r in &t.rows {
        out.push(
            std::iter::once(field(&r.index))
                .chain(r.cells.iter().map(|c| field(c)))
                .collect::<Vec<_>>()
                .join(";"),
        );
    }
    out.join("\r\n")
}

#[cfg(test)]
mod tests {
    use super::super::client::Value;
    use super::*;

    fn vb(oid: &[u32], value: Value) -> VarBind {
        VarBind {
            oid: oid.to_vec(),
            value,
        }
    }

    fn s(t: &str) -> Value {
        Value::Str(t.as_bytes().to_vec())
    }

    #[test]
    fn tabella_con_nome() {
        // walk of ifTable: columns 2 (ifDescr) and 8 (ifOperStatus), rows 1, 2 and 10;
        // row 10 has no status
        let t = [1, 3, 6, 1, 2, 1, 2, 2];
        let o = |c: u32, i: u32| [&t[..], &[1, c, i]].concat();
        let vbs = vec![
            vb(&o(2, 1), s("porta 1")),
            vb(&o(2, 2), s("porta 2")),
            vb(&o(2, 10), s("vlan10")),
            vb(&o(8, 1), Value::Int(1)),
            vb(&o(8, 2), Value::Int(2)),
        ];
        let tab = build(&t, &vbs).unwrap();
        assert_eq!(tab.name, "IF-MIB::ifTable");
        assert_eq!(
            tab.columns
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            ["ifDescr", "ifOperStatus"]
        );
        assert_eq!(tab.columns[0].oid, "1.3.6.1.2.1.2.2.1.2");
        assert_eq!(
            tab.rows,
            vec![
                Row {
                    index: "1".into(),
                    cells: vec!["porta 1".into(), "up".into()]
                },
                Row {
                    index: "2".into(),
                    cells: vec!["porta 2".into(), "down".into()]
                },
                Row {
                    index: "10".into(),
                    cells: vec!["vlan10".into(), String::new()]
                },
            ]
        );
        // a column asked for by name leads to the whole table
        assert_eq!(root(&mib::oid_of("ifDescr")), t.to_vec());
        assert_eq!(root(&t), t.to_vec());
    }

    #[test]
    fn tabella_senza_nome_e_indici_composti() {
        // private branch: <branch>.1.<column>.<two-number index>
        let t = [1, 3, 6, 1, 4, 1, 99999, 7];
        let o = |c: u32, i: [u32; 2]| [&t[..], &[1, c], &i[..]].concat();
        let vbs = vec![
            vb(&o(3, [1, 5]), Value::Gauge32(7)),
            vb(&o(3, [2, 1]), Value::Gauge32(9)),
            vb(&o(4, [1, 5]), s("a;b")),
        ];
        let tab = build(&t, &vbs).unwrap();
        assert_eq!(tab.name, ".1.3.6.1.4.1.99999.7");
        assert_eq!(tab.columns[0].name, "1.3.6.1.4.1.99999.7.1.3");
        assert_eq!(tab.rows[0].index, "1.5");
        assert_eq!(tab.rows[1].cells, vec!["9".to_string(), String::new()]);
        assert_eq!(
            csv(&tab),
            "Indice;1.3.6.1.4.1.99999.7.1.3;1.3.6.1.4.1.99999.7.1.4\r\n1.5;7;\"a;b\"\r\n2.1;9;"
        );
        // the same table read from the row (<branch>.1): the columns do not all start with 1
        let e = [&t[..], &[1]].concat();
        let tab2 = build(&e, &vbs).unwrap();
        assert_eq!(tab2.rows.len(), 2);
        assert_eq!(tab2.columns.len(), 2);
    }

    #[test]
    fn non_una_tabella() {
        assert!(build(&[1, 3, 6, 1, 2, 1, 2, 2], &[]).is_none());
        // a single value, without index: sysDescr.0 read as a "table" of system
        let vbs = vec![vb(&[1, 3, 6, 1, 2, 1, 1, 1, 0], s("x"))];
        let t = build(&[1, 3, 6, 1, 2, 1, 1], &vbs).unwrap();
        // single values become a row with index 0: this is how a group is read
        assert_eq!(t.rows.len(), 1);
        assert_eq!(t.rows[0].index, "0");
        assert_eq!(t.columns[0].name, "sysDescr");
    }

    #[test]
    fn english_csv_header() {
        let t = [1, 3, 6, 1, 2, 1, 1];
        let vbs = vec![vb(&[1, 3, 6, 1, 2, 1, 1, 1, 0], s("x"))];
        let tab = build(&t, &vbs).unwrap();
        assert!(csv(&tab).starts_with("Indice;"));
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        assert!(csv(&tab).starts_with("Index;"));
        assert!(!csv(&tab).contains("Indice"));
    }
}
