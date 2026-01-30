use super::*;

#[test]
fn acc_sha256_add() {
    let mut acc = AccSha256 {
        hash: [1, 2, 3, 4, 5, 6, 7, 8],
    };

    acc.add(b"hello world");
    assert_eq!(
        acc.hash,
        [
            4138495084, 3973010320, 2777164054, 2207796612, 615005229, 3241153105, 1397076350,
            2212452408
        ]
    );

    let mut acc = AccSha256::default();

    acc.add(b"secret");
    assert_eq!(
        acc.hash,
        [
            733482323, 2065540067, 2345861985, 2860865158, 3185633997, 1902313206, 2724194683,
            4113015387
        ]
    );
}

#[test]
fn to_hex() {
    assert_eq!(
        AccSha256::from("hellogoodbye").to_hex(),
        "3e4dc8cb9fce3f3e0aea6905faf58fd5baba4981c4f043ae03f58ef6a331de2f"
    );
    assert_eq!(
        AccSha256::from("").to_hex(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        AccSha256::from("1").to_hex(),
        "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
    );

    let acc = AccSha256 {
        hash: [65535, 1, 15, 256, 0xffffffff, 10, 0, 0],
    };
    assert_eq!(
        acc.to_hex().as_str(),
        "0000ffff000000010000000f00000100ffffffff0000000a0000000000000000"
    );

    let mut acc = AccSha256 {
        hash: [1, 2, 3, 4, 5, 6, 7, 8],
    };

    acc.add(b"hello world");
    assert_eq!(
        acc.to_hex().as_str(),
        "f6ac6c6ceccf5390a588291683984d8424a83c2dc13012515345b17e83df5838"
    );

    let more = [
        0x0a, 0x61, 0x20, 0x62, 0x69, 0x74, 0x20, 0x6d, 0x6f, 0x72, 0x65, 0x20, 0x74, 0x65, 0x78,
        0x74, 0x0a, 0x01, 0xc3, 0xb7, 0x00, 0x0a, 0x0a, 0x0a,
    ];

    assert_eq!(&more, &"\na bit more text\n\u{1}÷\0\n\n\n".as_bytes());
    acc.add(&more);
    assert_eq!(
        acc.to_hex().as_str(),
        "4cb301ea6c1e975ad8130be3e660b5a9ccf9e28e514a73c63533f2690c866255"
    );

    acc.add(b"363");
    acc.add("Ჾ蠇".as_bytes());
    assert_eq!(
        acc.to_hex().as_str(),
        "f8165b4e4696d5f09d0a08ed60f3503b9f4b15bf5bec95ad1fd7c85a43b00ead"
    );

    acc.add(vec!["1234567890"; 29].join("").as_bytes());

    assert_eq!(
        acc.to_hex().as_str(),
        "142513117c582aaca7a37386caada53880bf6b2e93be5b7fb6abf6e6c8ba504d"
    );
}

#[test]
fn to_id() {
    assert_eq!(AccSha256::from("hellogoodbye").to_id(), "hef112kz6HMarjX36");
    assert_eq!(AccSha256::from("").to_id(), "5aQFks5seW4uAZNtG");
    assert_eq!(AccSha256::from("1").to_id(), "RSaJD5Q8g5Jxp2s8M");
}
