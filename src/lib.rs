#[macro_use] extern crate error_chain;
extern crate reqwest;
extern crate crypto;
extern crate regex;
extern crate base64;

pub mod error;

use std::io::Read;
use std::ops::Deref;
use std::str;
use error::*;
use reqwest::Client;
use reqwest::header::{Connection, UserAgent};
use regex::Regex;
use crypto::{buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer };

#[derive(Debug)]
pub struct FileData {
    pub url: String,
    pub name: String,
    pub size: String
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
    pub name: String,
    pub pwd: String,
    pub files: Vec<FileData>,
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


pub fn decrypt_dlc(data: Vec<u8>, app_name: &str, dec_key: &[u8], dec_iv: &[u8]) -> Result<PkgData> {
    let data = decrypt_raw(data, app_name, dec_key, dec_iv)?;
    let data = String::from_utf8(data)?;
    let mut pkg = PkgData::new();

    let re = Regex::new(r#"<package ([^>]*)"#)?;
    let t = re.find(&data).ok_or("Can't find package in data")?;
    let (name, pwd) = match pkg_details(t.as_str().to_string()) {
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

/************ Private Functions *****************/

fn get_key(key: &[u8], app_name: &str) -> Result<Vec<u8>> {
    let url = "http://service.jdownloader.org/dlcrypt/service.php?srcType=dlc&destType=".to_string()
        + app_name + "&data=" + try!(str::from_utf8(key));

    let client = Client::new();
    let mut res = client.get(&url)
        .header(Connection::close())
        .header(UserAgent::new("Mozilla/5.3 (Windows; U; Windows NT 5.1; de; rv:1.8.1.6) Gecko/2232 Firefox/3.0.0.R"))
        .send()?;

    let mut key = Vec::new();
    res.read_to_end(&mut key)?;

    if key.len() != 33 {
        bail!("Unexpected Error");
    };
    // remove <rc> and </rc>
    let key = base64::decode(&key[4..28])?;

    Ok(key)
}

fn aes_decrypt(data: Vec<u8>, dec_key: &[u8], dec_iv: &[u8]) -> Result<Vec<u8>> {
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
        if dec.decrypt(&mut reader, &mut writer, true).is_err() {
            bail!("Can't decrypt");
        }
        if writer.is_empty() {
            break;
        }
        result.extend_from_slice(writer.take_read_buffer().take_remaining());
    };

    // remove tailing zeros
    result.retain(|x| *x !=  0 as u8);

    return Ok(result);
}

fn decrypt_raw(data: Vec<u8>, app_name: &str, dec_key: &[u8], dec_iv: &[u8]) -> Result<Vec<u8>> {
    let len = data.len();
    if len <= 88 {
        bail!("Corrupted data");
    };
    let (data, key) = data.split_at(len-88);

    let key = aes_decrypt(get_key(key, app_name)?, dec_key, dec_iv)?;

    let data = base64::decode(data)?;
    let data = aes_decrypt(data, key.deref(), key.deref())?;
    let data = base64::decode(&data)?;

    return Ok(data);
}

fn pkg_details(data: String) -> Result<(String, String)> {
    let re = Regex::new(r#"name="([^"])*""#)?;
    let t = re.find(&data).ok_or("Can't find name in data")?;
    let name = String::from_utf8(base64::decode(t.as_str())?)?;

    let re = Regex::new(r#"passwords="([^"])*""#)?;
    let t = re.find(&data).ok_or("Can't find password in data")?;
    let pwd = String::from_utf8(base64::decode(&t.as_str())?)?;

    Ok((name, pwd))
}

fn file_details(data: String, pos: usize) -> String {
    let buf: String = match base64::decode(&data[pos..]) {
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