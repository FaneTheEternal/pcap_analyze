use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::vec::IntoIter;

pub fn save<const I: usize, const O: usize>(
    data: &[([f32; I], [f32; O])],
    headers_data: [String; I],
    headers_target: [String; O],
) -> Result<(), Box<dyn Error>>
{
    let mut wtr = csv::Writer::from_path("data_set.csv")?;
    wtr.write_record(headers_data.into_iter().chain(headers_target))?;
    for (row, target) in data {
        let s_iter = row.into_iter()
            .chain(target)
            .map(|e| e.to_string())
            .collect::<Vec<_>>();
        wtr.write_record(s_iter)?;
    }
    wtr.flush()?;
    Ok(())
}

pub fn csv_write_file<P, I, II, S>(
    path: P,
    data: I,
) -> Result<(), Box<dyn Error>>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item=II>,
        II: IntoIterator<Item=S>,
        S: std::fmt::Display + Sized,
{
    let mut wrt = csv::Writer::from_path(path)?;
    for row in data {
        let row = row.into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>();
        wrt.write_record(row)?;
    }
    wrt.flush()?;
    Ok(())
}
