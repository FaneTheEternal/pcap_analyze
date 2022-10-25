use crate::*;


#[derive(Layer)]
pub struct GOOSE {
    pub app_id: u8,
    pub len: u8,
    pub reserved1: u8,
    pub reserved2: u8,
    // TODO
}

impl GOOSE {
    pub fn new(data: &[u8]) -> GOOSE {
        let app_id = *data.get(0).unwrap();
        let len = *data.get(1).unwrap();
        let reserved1 = *data.get(2).unwrap();
        let reserved2 = *data.get(3).unwrap();
        GOOSE {
            app_id,
            len,
            reserved1,
            reserved2
        }
    }
}
