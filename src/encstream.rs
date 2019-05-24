use std::io;
use crate::EncryptedDuplexStream;

struct EncRw<Stream> {
    underlying: EncryptedDuplexStream<Stream>,
    write_leftovers: ([u8; 65519], usize),
    read_leftovers: ([u8; 65519], usize),
}

/// https://doc.rust-lang.org/std/io/trait.Write.html
/// >> A call to write represents at most one attempt to write to any wrapped object.
/// For lack of a conformant solution, we currently disregard this rule by calling
/// write_all. yolo
/// TODO: don't call write_all
impl<Stream: io::Write> io::Write for crate::EncRw<Stream> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let chunk = buf.len().min(65519);
        self.send(chunk)?;
        Ok(chunk)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.underlying.flush()
    }
}

impl<Stream: io::Read> io::Read for crate::EncryptedDuplexStream<Stream> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        
    }
}
