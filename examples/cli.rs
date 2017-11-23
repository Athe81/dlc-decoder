extern crate dlc_decrypter;

use std::env;
use dlc_decrypter::DlcDecoder;

fn main() {
    // Create the DlcDecoder
    let dd = DlcDecoder::new();

    // loop over all arguments for the programm
    // skip the first one because it's the programm
    // own name
    for arg in env::args().skip(1) {
        // hand over the file path
        let dlc = dd.from_file(arg);

        // print the result
        println!("DLC: {:?}", dlc);
    }
}