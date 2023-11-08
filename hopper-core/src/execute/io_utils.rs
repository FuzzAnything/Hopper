use std::io::BufRead;

use eyre::Context;

use crate::{Deserialize, Deserializer};

pub fn read_line<R: BufRead>(reader: &mut R) -> eyre::Result<String> {
    let mut buf = String::new();
    let n = reader
        .read_line(&mut buf)
        .with_context(|| format!("fail to read line: {buf}"))?;
    if n == 0 {
        crate::log!(warn, "read EOF, the other side may be down...");
        eyre::bail!(crate::HopperError::ReadLineEOF);
    }
    trim_newline(&mut buf);
    Ok(buf)
}

pub fn receive_line<R: BufRead, T: Deserialize>(reader: &mut R) -> eyre::Result<T> {
    let buf = read_line(reader)?;
    let mut de = Deserializer::new(&buf, None);
    let ret = T::deserialize(&mut de);
    if ret.is_err() {
        crate::log!(warn, "fail to parse: {buf}");
    }
    ret.with_context(|| format!("fail to parse : {}", &buf))
}

/// Trim newline chars in lines.
pub fn trim_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}
