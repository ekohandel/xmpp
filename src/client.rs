use crate::Connection;
use std::io::Result;

pub struct Client {
    conn: Box<dyn Connection>,
}

impl Client {
    pub fn new(conn: Box<dyn Connection>) -> Self {
        Client { conn }
    }

    pub fn connect(&mut self) -> Result<()> {
        self.conn.connect()
    }
}
