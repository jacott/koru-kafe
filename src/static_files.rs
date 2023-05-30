use hyper::{
    header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE},
    Body, Request, Response,
};
use std::io;
use tokio::fs;

pub async fn send_file(req: Request<Body>, root: &str) -> crate::Result<Response<Body>> {
    let url_path = req.uri().path();
    if !(url_path.contains('\\') || url_path.ends_with("/..") || url_path.contains("/../")) {
        let headers = req.headers();
        let mut path = root.to_string();
        path += url_path;
        let len = path.len();

        let mime_type = mime_guess::from_path(&path).first_or_text_plain().to_string();

        let encodings = if let Some(v) = headers.get(ACCEPT_ENCODING) { v.as_bytes() } else { b"" };

        for enc in ENCODINGS.iter() {
            let unencryped = enc.is_empty();
            let prefix;
            if !unencryped {
                if !can_compress(enc, encodings) {
                    continue;
                }
                prefix = std::str::from_utf8(enc).unwrap();
                path += ".";
                path += prefix;
            } else {
                prefix = ""
            }
            match fs::read(&path).await {
                Ok(body) => {
                    let mut rb = Response::builder().status(200).header(CONTENT_TYPE, mime_type);
                    if !unencryped {
                        rb = rb.header(CONTENT_ENCODING, prefix.to_string());
                    }

                    return Ok(rb.body(Body::from(body))?);
                }
                Err(err) => match err.kind() {
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => {}
                    _ => return Ok(Response::builder().status(500).body(Body::from(err.to_string()))?),
                },
            }
            path.truncate(len);
        }
    }

    eprintln!("{} 404", url_path);
    Ok(Response::builder().status(404).body(Body::from("Not found\n"))?)
}

fn can_compress(enc: &[u8], encodings: &[u8]) -> bool {
    if encodings.is_empty() {
        return true;
    }
    let mut iter = encodings.iter();

    'find_word: loop {
        let mut enc = enc.iter();
        match enc.next() {
            None => return true,
            Some(c) => {
                let mut word_boundry = true;
                if let Some(v) = iter.find(|v| {
                    // find first letter
                    let v = **v;
                    if word_boundry && (v == b'*' || v.eq_ignore_ascii_case(c)) {
                        return true;
                    }
                    word_boundry = v < b'@';
                    false
                }) {
                    // find remainder
                    if *v != b'*' {
                        for c in enc {
                            match iter.next() {
                                None => return false,
                                Some(v) if !c.eq_ignore_ascii_case(v) => {
                                    if *v != b',' && !iter.any(|v| *v == b',') {
                                        return false;
                                    }
                                    continue 'find_word;
                                }
                                _ => (),
                            }
                        }
                    }
                    match iter.find(|v| **v != b' ') {
                        // skip WS
                        None | Some(b',') => return true,
                        Some(b';') => {
                            match iter.find(|v| **v != b' ') {
                                Some(b'q') => {
                                    // find ;q=0
                                    for c in b"=0" {
                                        match iter.next() {
                                            None => return true,
                                            Some(v) => {
                                                if v != c {
                                                    return true;
                                                }
                                            }
                                        }
                                    }
                                    // find ! ;q=0(.0*)
                                    match iter.find(|v| !matches!(**v, b' ' | b'.' | b'0')) {
                                        None => return false,
                                        Some(b',') => continue 'find_word,
                                        _ => return true,
                                    }
                                }
                                _ => return true,
                            }
                        }
                        _ => {
                            if iter.any(|v| *v == b',') {
                                continue 'find_word;
                            }
                            return false;
                        }
                    }
                }
                return false;
            }
        }
    }
}

static ENCODINGS: [&[u8]; 2] = [b"br", b""];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_compress() {
        assert!(!can_compress(b"br", b"abc,br  ;   q=0,gzip"));
        assert!(!can_compress(b"br", b"abc,br;q=0,gzip"));
        assert!(!can_compress(b"br", b"abc,br;q=0,gzip"));
        assert!(!can_compress(b"br", b"abc,br:,gzip"));
        assert!(!can_compress(b"br", b"abc,gzip"));
        assert!(!can_compress(b"br", b"abc,br:"));
        assert!(!can_compress(b"br", b"abc,gzip,*;q=0,foo"));
        assert!(!can_compress(b"br", b"abc,gzip,br   ;q=0"));
        assert!(!can_compress(b"br", b"abc,gzip,*;q=0"));

        assert!(can_compress(b"br", b"br"));
        assert!(can_compress(b"br", b"abc,br;"));
        assert!(can_compress(b"br", b"abc,br "));
        assert!(can_compress(b"br", b"abc  ,   br , gzip"));
        assert!(can_compress(b"br", b"abc, Br ;   q=0.001,gzip"));
        assert!(can_compress(b"br", b"abc,Br;q=0.001,gzip"));
        assert!(can_compress(b"br", b"abc,Br;q=1,gzip"));
        assert!(can_compress(b"br", b""));
        assert!(can_compress(b"br", b"abc,gzip,*"));
        assert!(can_compress(b"br", b"abc,gzip,*;q=0.1"));
    }
}
