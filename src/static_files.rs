use httpdate::HttpDate;
use hyper::{header, http::HeaderValue, Body, Method, Request, Response};
use std::{io, time::SystemTime};
use tokio::fs;

#[derive(Debug)]
pub struct Opts {
    pub root: String,
    pub cache_control: String,
}

pub async fn send_file(req: Request<Body>, opts: &Opts) -> crate::Result<Response<Body>> {
    let url_path = req.uri().path();
    if url_path.contains('\\') || url_path.ends_with("/..") || url_path.contains("/../") {
        return Ok(Response::builder().status(400).body(Body::from("Bad Request\n"))?);
    }

    let headers = req.headers();
    let mut path = opts.root.to_string();
    path += url_path;
    let len = path.len();

    let mime_type = mime_guess::from_path(&path).first_or_text_plain().to_string();

    let encodings = if let Some(v) = headers.get(header::ACCEPT_ENCODING) { v.as_bytes() } else { b"" };

    let if_modified_since = read_time(&headers.get(header::IF_MODIFIED_SINCE));

    for (enc, prefix) in ENCODINGS.iter() {
        path.truncate(len);

        let unencryped = enc.is_empty();
        if !unencryped {
            if !can_compress(enc, encodings) {
                continue;
            }

            path += ".";
            path += prefix;
        }
        if let Ok(md) = fs::metadata(&path).await {
            let last_modified = crate::round_time_secs(md.modified().expect("modified not supported"));

            let mut rb = Response::builder()
                .header(header::CONTENT_TYPE, &mime_type)
                .header(header::LAST_MODIFIED, HttpDate::from(last_modified).to_string())
                .header(header::CACHE_CONTROL, &opts.cache_control);
            if !unencryped {
                rb = rb.header(
                    header::CONTENT_ENCODING,
                    std::str::from_utf8(enc).expect("ENCODINGS bug"),
                )
            }

            if let Some(if_modified_since) = if_modified_since {
                if if_modified_since == last_modified {
                    return Ok(rb.status(304).body(Body::empty())?);
                }
            }

            if req.method() == Method::HEAD {
                return Ok(rb.status(200).body(Body::empty())?);
            }

            return match fs::read(&path).await {
                Ok(body) => Ok(rb.status(200).body(Body::from(body))?),
                Err(err) => match err.kind() {
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => {
                        continue;
                    }
                    _ => Ok(Response::builder().status(500).body(Body::from(err.to_string()))?),
                },
            };
        }
    }

    Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "Not Found")))
}

fn read_time(value: &Option<&HeaderValue>) -> Option<SystemTime> {
    if let Some(value) = value {
        std::str::from_utf8(value.as_bytes())
            .ok()
            .and_then(|value| httpdate::parse_http_date(value).ok())
    } else {
        None
    }
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

static ENCODINGS: [(&[u8], &str); 3] = [(b"br", "br"), (b"gzip", "gz"), (b"", "")];

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

    #[tokio::test]
    async fn send_file_cached() -> crate::Result<()> {
        let opts = Opts {
            root: "tests/assets".to_string(),
            cache_control: "max-age=2000".to_string(),
        };

        let req = Request::builder().uri("/hello.txt").body(Body::empty()).unwrap();

        let res = super::send_file(req, &opts).await.unwrap();

        assert_eq!(res.status().as_u16(), 200);
        assert_eq!(res.headers().get(header::CONTENT_ENCODING).unwrap(), "br");
        assert_eq!(res.headers().get(header::CACHE_CONTROL).unwrap(), "max-age=2000");

        Ok(())
    }
}
