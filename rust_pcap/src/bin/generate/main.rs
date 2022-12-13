use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::ops::{AddAssign, Mul};
use rand::{Rng, thread_rng};

const COUNT: f32 = 77.0;
const SIZE: f32 = 78.65714;
const ADDRESSES: f32 = 7.0;
// const REQ: f32 = 46.0;
// const RES: f32 = 31.0;

const I: usize = 10_000;
const STEP: usize = I / 5;

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
struct Row(f32, f32, f32, f32);

impl Hash for Row {
    fn hash<H: Hasher>(&self, state: &mut H) {
        format!("{:?}", self).hash(state);
    }
}

impl Eq for Row {}


fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = thread_rng();
    let mut wrt = csv::Writer::from_path("data_set_generated.csv")?;
    wrt.write_record([
        "count", "size", "addresses", "req", "res", "unr",
        "over_count", "over_size", "over_addr", "has_unr",
    ])?;
    let mut rows = HashMap::<Row, usize>::new();
    for i in 0..I {
        if i % STEP == 0 {
            print!("{}...", i);
        }
        let count = rng.gen_range(1.0..(COUNT * 2.0));
        let size = rng.gen_range(1.0..(SIZE * 2.0));
        let addresses = rng.gen_range(2.0..(ADDRESSES * 1.5));
        let hlf = count / 2.0;
        let (req, res, unr) = if rng.gen_bool(1.0 / 2.0) {
            (hlf, hlf, 0.0)
        } else {
            let req = rng.gen_range(hlf..=count);
            let res = count - req;
            (req, res, req - res)
        };
        let over_count = if count > COUNT { 1.0 } else { 0.0 };
        let over_size = if size > SIZE { 1.0 } else { 0.0 };
        let over_addr = if addresses > ADDRESSES { 1.0 } else { 0.0 };
        let has_unr = if unr > 0.0 { 1.0 } else { 0.0 };
        let record = [
            count,
            size,
            addresses,
            req,
            res,
            unr,
            over_count,
            over_size,
            over_addr,
            has_unr,
        ];
        wrt.write_record(record.map(|e| e.to_string()))?;

        match rows.entry(Row(over_count, over_size, over_addr, has_unr)) {
            Entry::Occupied(mut oc) => {
                oc.get_mut().add_assign(1);
            }
            Entry::Vacant(vac) => {
                vac.insert(1);
            }
        }
    }
    wrt.flush()?;
    println!("{}", I);

    let parts = rows.iter()
        .fold((0.0, 0.0, 0.0, 0.0), |acc, row| {
            (
                acc.0 + row.0.0.mul(*row.1 as f32),
                acc.1 + row.0.1.mul(*row.1 as f32),
                acc.2 + row.0.2.mul(*row.1 as f32),
                acc.3 + row.0.3.mul(*row.1 as f32),
            )
        });
    println!("{:^12} {:^12} {:^12} {:^12}", "over_count", "over_size", "over_addr", "has_unr");
    println!("{:^12} {:^12} {:^12} {:^12}",
             p(parts.0), p(parts.1), p(parts.2), p(parts.3));
    for (row, count) in rows {
        println!("{:^12} {:^12} {:^12} {:^12}: {}",
                 row.0, row.1, row.2, row.3, p(count as f32));
    }
    Ok(())
}

fn p(n: f32) -> f32 {
    const IF32: f32 = I as f32;
    (n / IF32) * 100.0
}
