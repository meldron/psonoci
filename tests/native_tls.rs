#![cfg(target_os = "linux")]

use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509, X509NameBuilder};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

#[test]
fn native_tls_uses_the_patched_lts_library() {
    assert_eq!(openssl::version::version(), "OpenSSL 3.5.9 29 Sep 2026");
}

#[test]
fn native_tls_completes_a_verified_https_request() {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate.set_pubkey(&key).unwrap();
    certificate
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&certificate.x509v3_context(None, None))
        .unwrap();
    certificate.append_extension(san).unwrap();
    certificate.sign(&key, MessageDigest::sha256()).unwrap();
    let certificate = certificate.build();
    let root = reqwest::Certificate::from_der(&certificate.to_der().unwrap()).unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.set_certificate(&certificate).unwrap();
    acceptor.check_private_key().unwrap();
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut stream = acceptor.accept(socket).unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 16384);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    let client = reqwest::blocking::Client::builder()
        .use_native_tls()
        .add_root_certificate(root)
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let response = client
        .get(format!("https://localhost:{}", address.port()))
        .send()
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().unwrap(), "ok");
    server.join().unwrap();
}
