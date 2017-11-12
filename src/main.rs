extern crate dlc_decrypter;

use dlc_decrypter::*;
use dlc_decrypter::error::*;

use std::env;
use std::io::Read;
use std::fs::File;

fn read_file(file: &str) -> Result<Vec<u8>> {
    let mut f = try!(File::open(&file));
    let mut data = Vec::new();
    try!(f.read_to_end(&mut data));
    Ok(data)
}

fn main() {
    let app_name = "pylo";
    let dec_key = b"cb99b5cbc24db398";
    let dec_iv = b"9bc24cb995cb8db3";

    for arg in env::args().skip(1){
        let data = match read_file(&arg) {
            Ok(data) => data,
            Err(err) => {
                println!("Error: '{}' {}", &arg, err);
                continue;
            },
        };

        let s = match decrypt_dlc(data, &app_name, dec_key, dec_iv) {
            Ok(s)    => s,
            Err(err) => {
                println!("Error: '{}' {}", &arg, err);
                continue;
            },
        };

        println!("{} as XML:\n{:?}", &arg, s);
    }
}
