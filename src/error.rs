error_chain!{

    types {
        Error, ErrorKind, ResultExt, Result;
    }

    foreign_links {
        Fmt(::std::fmt::Error);
        Io(::std::io::Error);
        FormBase64(::rustc_serialize::base64::FromBase64Error);
        //CipherError(::crypto::symmetriccipher::SymmetricCipherError);
        Utf8(::std::str::Utf8Error);
        FromUtf8(::std::string::FromUtf8Error);
        Reqwest(::reqwest::Error);
    }
}