use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::ops::{AddAssign, Range};
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

fn gen_fixed_range(rng: &mut impl Rng, range: Range<f32>) -> f32
{
    rng.gen_range(range) as usize as f32
}

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
        let count = gen_fixed_range(&mut rng, 1.0..(COUNT * 1.99));
        let size = rng.gen_range(1.0..(SIZE * 2.0));
        let addresses = gen_fixed_range(&mut rng, 2.0..(ADDRESSES * 1.99));
        let hlf = count / 2.0;
        let (req, res, unr) = if rng.gen_bool(1.0 / 2.1) {
            (hlf, hlf, 0.0)
        } else {
            let req = gen_fixed_range(&mut rng, hlf..count);
            let res = count - req;
            (req, res, (req - res).max(0.0))
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

    rust_pcap::print_csv_stats(
        "data_set_generated.csv",
        6..10,
        &["over_count", "over_size", "over_addr", "has_unr"],
    )?;
    Ok(())
}
