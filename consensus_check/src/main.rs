// Reads lines "name spk_hex tx_hex input_idx expect(0/1)" and runs Core's consensus interpreter.
use bitcoinconsensus::{verify_with_flags, VERIFY_ALL_PRE_TAPROOT};
use std::io::{self, BufRead};
fn main() {
    let mut bad = 0;
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 5 { continue; }
        let spk = hex::decode(f[1]).unwrap();
        let tx = hex::decode(f[2]).unwrap();
        let idx: usize = f[3].parse().unwrap();
        let expect = f[4] == "1";
        let r = verify_with_flags(&spk, 0, &tx, None, idx, VERIFY_ALL_PRE_TAPROOT);
        let ok = r.is_ok();
        if ok != expect { bad += 1; }
        println!("{:4} {:60} consensus={} {}", if ok == expect { "PASS" } else { "FAIL" }, f[0],
                 if ok { "VALID".to_string() } else { format!("INVALID({:?})", r.err().unwrap()) },
                 if ok == expect { "" } else { "<-- unexpected" });
    }
    println!("unexpected results: {}", bad);
}
