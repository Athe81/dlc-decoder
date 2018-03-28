# dlc-decrypter

A simple library to decode dlc files to a readable format.

## Usage
Add `dlc_decrypter` as a dependency in `Cargo.toml`:
```toml
[dependencies]
dlc-decrypter = "0.2.0"
```

Use the `dlc_decrypter::DlcDecoder' to decrypt a .dlc file or datapackage:
```rust
extern crate dlc_decrypter;

fn main() {
    // Create the DlcDecoder
    let dd = dlc_decrypter::DlcDecoder::new();

    // loop over all arguments for the programm
    // skip the first one because it's the programm
    // own name
    for arg in std::env::args().skip(1) {
        // hand over the file path
        let dlc = dd.from_file(arg);

        // print the result
        println!("DLC: {:?}", dlc);
    }
}
```

## Thanks
* [Bubblepoint](https://github.com/Bubblepoint) for creating and maintaing the crate.
* [Robert Sch&uuml;tte](https://github.com/Roba1993) for doing a great refactoring.

## License
Distributed under the [MIT License](LICENSE).
