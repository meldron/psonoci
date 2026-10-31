use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use psonoci::config::{Config, HttpOptions, PsonoSettings};
use psonoci::sensitive::SensitiveString;
use serde_json::Value;
use uuid::Uuid;

pub const API_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Value,
}

pub struct Server {
    pub config: Config,
    requests: Receiver<Request>,
    handle: JoinHandle<()>,
}

impl Server {
    pub fn start(responses: Vec<(u16, Value)>) -> Self {
        let count = responses.len();
        let mut responses = responses.into_iter();
        Self::with_handler(count, move |_| responses.next().unwrap())
    }

    pub fn with_handler<F>(count: usize, mut handler: F) -> Self
    where
        F: FnMut(&Request) -> (u16, Value) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, requests) = mpsc::channel();
        let handle = thread::spawn(move || {
            for _ in 0..count {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "expected HTTP request was not sent"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept failed: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let request = read_request(&mut stream);
                let (status, body) = handler(&request);
                sender.send(request).unwrap();
                let body = body.to_string();
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let config = Config {
            psono_settings: PsonoSettings {
                api_key_id: Uuid::new_v4(),
                api_secret_key_hex: SensitiveString::from(API_KEY),
                server_url: format!("http://{address}/server/").parse().unwrap(),
            },
            http_options: HttpOptions {
                timeout: 5,
                ..Default::default()
            },
        };
        Self {
            config,
            requests,
            handle,
        }
    }

    pub fn finish(self) -> Vec<Request> {
        self.handle.join().unwrap();
        self.requests.into_iter().collect()
    }
}

fn read_request(stream: &mut TcpStream) -> Request {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
        assert!(header.len() < 64 * 1024);
    }
    let header = String::from_utf8(header).unwrap();
    let mut first = header.lines().next().unwrap().split_whitespace();
    let method = first.next().unwrap().to_owned();
    let path = first.next().unwrap().to_owned();
    let length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    Request {
        method,
        path,
        body: serde_json::from_slice(&body).unwrap(),
    }
}
