use std::io::Result;

pub trait Connection {
    fn connect(&mut self) -> Result<()>;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn write(&mut self, buf: &[u8]) -> Result<usize>;
    fn flush(&mut self) -> Result<()>;
    fn close(&mut self) -> Result<()>;
}
