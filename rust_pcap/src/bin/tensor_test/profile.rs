use std::error::Error;
use std::io::Write;
use std::path::Path;
use serde::{Serialize, Deserialize};
use crate::gtrain;

#[derive(Debug)]
pub struct LearnInstance<const I: usize, const O: usize> {
    cfg: Vec<u64>,
    data: Vec<([f32; I], [f32; O])>,
}

impl<const I: usize, const O: usize> LearnInstance<I, O> {
    pub fn make(cfg: &[u64], data: &[([f32; I], [f32; O])]) -> Self {
        LearnInstance {
            cfg: cfg.to_vec(),
            data: data.to_vec(),
        }
    }

    pub fn invoke(self) -> Result<(), Box<dyn Error>> {
        let path = self.cfg.iter()
            .map(|e| { e.to_string() })
            .collect::<Vec<_>>()
            .join("-");
        let errors = gtrain(
            &path,
            &self.data,
            &self.cfg,
        )?;
        todo!("SAFE");
        Ok(())
    }
}
