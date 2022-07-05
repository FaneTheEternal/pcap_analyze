use std::error::Error;
use std::io::{Read, Write};
use std::path::Path;
use serde::{Serialize, Deserialize};
use tracing_subscriber::filter::targets::IntoIter;
use crate::gtrain;


#[derive(Default, Debug, Serialize, Deserialize)]
pub struct State {
    done: Vec<Vec<String>>,
}

impl State {
    const FILE: &'static str = "state.ron";

    pub fn get() -> State {
        let mut file = std::fs::File::options()
            .create(true).write(true).read(true)
            .open(Self::FILE).unwrap();
        let mut s = String::new();
        file.read_to_string(&mut s).unwrap();
        ron::from_str(&s).unwrap_or_else(|_| { Self::default() })
    }

    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        let mut file = std::fs::File::options()
            .create(true).truncate(true).write(true)
            .open(Self::FILE)?;
        file.write(ron::ser::to_string_pretty(self, Default::default())?.as_bytes())?;
        Ok(())
    }

    pub fn is_done(&self, name: String) -> bool {
        self.done.iter().find(|e| { e.first().unwrap().eq(&name) }).is_some()
    }

    pub fn append<I, S>(&mut self, row: I) -> Result<(), Box<dyn Error>>
        where
            I: IntoIterator<Item=S>,
            S: std::fmt::Display + Sized,
    {
        let row = row.into_iter()
            .map(|e| e.to_string())
            .collect();
        self.done.push(row);
        self.save()
    }
}

impl IntoIterator for State {
    type Item = Vec<String>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.done.into_iter()
    }
}
