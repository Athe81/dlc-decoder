extern crate rustc_serialize;
extern crate hyper;
extern crate crypto;
extern crate regex;

use std::io;
use std::io::Read;
use std::ops::Deref;
use std::fmt;
use std::str;

use regex::Regex;
use rustc_serialize::base64::{ FromBase64, FromBase64Error };

use hyper::Client;
use hyper::header::{Connection, UserAgent};

use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer };
use crypto::symmetriccipher::{ Decryptor, SymmetricCipherError };

#[derive(Debug)]
pub enum DLCError {
    Io(io::Error),
    Base64(FromBase64Error),
    Hyper(hyper::error::Error),
    Crypto(symmetriccipher::SymmetricCipherError),
    StrUtf8(str::Utf8Error),
    StringUtf8(std::string::FromUtf8Error),
    Corrupted,
    Unexpected,
}

impl From<io::Error> for DLCError {
    fn from(err: io::Error) -> DLCError {
        DLCError::Io(err)
    }
}

impl From<FromBase64Error> for DLCError {
    fn from(err: FromBase64Error) -> DLCError {
        DLCError::Base64(err)
    }
}

impl From<hyper::error::Error> for DLCError {
    fn from(err: hyper::error::Error) -> DLCError {
        DLCError::Hyper(err)
    }
}

impl From<symmetriccipher::SymmetricCipherError> for DLCError {
    fn from(err: symmetriccipher::SymmetricCipherError) -> DLCError {
        DLCError::Crypto(err)
    }
}

impl From<str::Utf8Error> for DLCError {
    fn from(err: str::Utf8Error) -> DLCError {
        DLCError::StrUtf8(err)
    }
}

impl From<std::string::FromUtf8Error> for DLCError {
    fn from(err: std::string::FromUtf8Error) -> DLCError {
        DLCError::StringUtf8(err)
    }
}

impl fmt::Display for DLCError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DLCError::Io(ref err) => err.fmt(f),
            DLCError::Base64(ref err) => err.fmt(f),
            DLCError::Hyper(ref err) => err.fmt(f),
            DLCError::Crypto(_) => write!(f, "Decryption failed."),
            DLCError::StrUtf8(ref err) => err.fmt(f),
            DLCError::StringUtf8(ref err) => err.fmt(f),
            DLCError::Corrupted   => write!(f, "File is corrupted."),
            DLCError::Unexpected   => write!(f, "Unexpected data from service.jdownloader.org."),
        }
    }
}

#[derive(Debug)]
pub struct FileData {
    url: String,
    name: String,
    size: String
}

impl FileData {
    fn new() -> FileData {
        FileData {
            url: String::new(),
            name: String::new(),
            size: String::new(),
        }
    }
}

#[derive(Debug)]
pub struct PkgData {
    name: String,
    pwd: String,
    files: Vec<FileData>,
}

impl PkgData {
    fn new() -> PkgData {
        PkgData {
            name: String::new(),
            pwd: String::new(),
            files: Vec::new(),
        }
    }
}

fn get_key(key: &[u8], app_name: &str) -> Result<Vec<u8>, DLCError> {
    let client = Client::new();
    let url = "http://service.jdownloader.org/dlcrypt/service.php?srcType=dlc&destType=".to_string()
        + app_name + "&data=" + try!(str::from_utf8(key));
    let mut res = try!(client.get(&url)
        .header(Connection::close())
        // UserAgent is important
        .header(UserAgent("Mozilla/5.3 (Windows; U; Windows NT 5.1; de; rv:1.8.1.6) Gecko/2232 Firefox/3.0.0.R".to_string()))
        .send());

    let mut key = Vec::new();
    try!(res.read_to_end(&mut key));

    if key.len() != 33 {
        return Err(DLCError::Unexpected);
    };
    // remove <rc> and </rc>
    let key = key[4..28].to_vec();
    let key = try!(key.from_base64());

    return Ok(key);
}

fn aes_decrypt(data: Vec<u8>, dec_key: &[u8], dec_iv: &[u8]) -> Result<Vec<u8>, DLCError> {
    let mut out = [0; 4096];
    let mut reader = buffer::RefReadBuffer::new(data.deref());
    let mut writer = buffer::RefWriteBuffer::new(&mut out);
    let mut dec = aes::cbc_decryptor(
        aes::KeySize::KeySize128,
        dec_key,
        dec_iv,
        blockmodes::NoPadding,
    );

    let mut result = Vec::new();
    loop {
        try!(dec.decrypt(&mut reader, &mut writer, true));
        if writer.is_empty() {
            break;
        }
        result.extend_from_slice(writer.take_read_buffer().take_remaining());
    };

    // remove tailing zeros
    result.retain(|x| *x !=  0 as u8);

    return Ok(result);
}

fn decrypt_raw(data: Vec<u8>, app_name: &str, dec_key: &[u8], dec_iv: &[u8]) -> Result<Vec<u8>, DLCError> {
    let len = data.len();
    if len <= 88 {
        return Err(DLCError::Corrupted);
    };
    let (data, key) = data.split_at(len-88);

    let key = try!(get_key(key, app_name));
    let key = try!(aes_decrypt(key, dec_key, dec_iv));

    let data = try!(data.from_base64());
    let data = try!(aes_decrypt(data, key.deref(), key.deref()));
    let data = try!(data.from_base64());

    return Ok(data);
}

fn pkg_details(data: String) -> Result<(String, String), DLCError> {
    let re = Regex::new(r#"name="([^"])*""#).unwrap();
    let (s, e) = re.find(&data).unwrap();
    let name = data[s+6..e-1].to_string();

    let re = Regex::new(r#"passwords="([^"])*""#).unwrap();
    let (s, e) = re.find(&data).unwrap();
    let pwd = data[s+11..e-1].to_string();

    let name = try!(name.from_base64());
    let name = try!(String::from_utf8(name));
    let pwd = try!(pwd.from_base64());
    let pwd = try!(String::from_utf8(pwd));

    Ok((name, pwd))
}

fn file_details(data: String, pos: usize) -> String {
    let buf: String = match data[pos..].from_base64() {
        Ok(x)  => {
            match String::from_utf8(x) {
                Ok(x)  => x,
                Err(_) => data[pos..].to_string(),
            }
        },
        Err(_) => data[pos..].to_string(),
    };
    buf
}

pub fn decrypt_dlc(data: Vec<u8>, app_name: &str, dec_key: &[u8], dec_iv: &[u8]) -> Result<PkgData, DLCError> {
    let data = try!(decrypt_raw(data, app_name, dec_key, dec_iv));
    let data = try!(String::from_utf8(data));
    // let data = data.trim();
    let mut pkg = PkgData::new();

    let re = Regex::new(r#"<package ([^>]*)"#).unwrap();
    let (s, e) = re.find(&data).unwrap();
    let (name, pwd) = match pkg_details(data[s..e].to_string()) {
        Ok((name, pwd)) => (name, pwd),
        Err(_)          => (String::new(), String::new()),
    };
    pkg.name = name;
    pkg.pwd = pwd;

    let files_xml: Vec<&str> = data.split("<file>").collect();
    for f in files_xml {
        let details: Vec<&str> = f.split("<").collect();
        let mut file = FileData::new();
        for d in details {
            if d.len() > 3 && d[..3] == "url".to_string() {
                let buf = file_details(d.to_string(), 4);
                file.url = buf;
            } else if d.len() > 8 && d[..8] == "filename".to_string() {
                let buf = file_details(d.to_string(), 9);
                file.name = buf;
            } else if d.len() > 4 && d[..4] == "size".to_string() {
                let buf = file_details(d.to_string(), 5);
                file.size = buf;
            }
        }
        pkg.files.push(file);
    };

    return Ok(pkg);
}
