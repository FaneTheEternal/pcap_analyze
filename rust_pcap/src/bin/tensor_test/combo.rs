use std::collections::HashSet;
use std::ops::Index;

pub type _TYPE = u32;

pub struct WORD {
    alph: Vec<_TYPE>,
    len: usize,

    _state: Option<Vec<Digit>>,
}

impl WORD {
    pub fn new(alph: Vec<_TYPE>, len: usize) -> WORD {
        WORD {
            alph,
            len,
            _state: None,
        }
    }
}

impl Iterator for WORD {
    type Item = Vec<_TYPE>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut state = self._state.take()
            .or_else(|| {
                Some(vec![Digit::new(self.alph.clone()); self.len])
            })
            .unwrap();

        let mut add = 1;
        for i in 0..self.len {
            add = state[i].inc(add);
        }

        if add > 0 {
            return None;
        }

        self._state.replace(state.clone());
        Some(state.into_iter().map(|e| e.value).collect())
    }
}

#[derive(Clone)]
pub struct Digit {
    alph: Vec<_TYPE>,
    pub value: _TYPE,
}

impl Digit {
    pub fn new(alph: Vec<_TYPE>) -> Digit {
        let value = *alph.first().unwrap();
        Digit { alph, value }
    }

    pub fn inc(&mut self, inc: usize) -> usize {
        let mut ret = 0;
        for _ in 0..inc {
            if self.alph.last().unwrap().eq(&self.value) {
                self.value = *self.alph.first().unwrap();
                ret += 1;
            } else {
                let cur = self.alph.iter().position(|e| e.eq(&self.value)).unwrap();
                self.value = *self.alph.get(cur + 1).unwrap();
            }
        }
        ret
    }
}
