use std::{
    env,
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

use faultline_common::FAULTLINE_LAB_APPLICATION;

const APPLICATION_NAME: &str = FAULTLINE_LAB_APPLICATION;

fn main() -> ExitCode {
    match run() {
        Ok(success) => {
            if success {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("{APPLICATION_NAME}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("server") => {
            let address = value(&arguments, "--bind")?.parse()?;
            serve(address)?;
            Ok(true)
        }
        Some("client") => {
            let client = ClientSpec::parse(&arguments)?;
            Ok(client.run())
        }
        Some("transfer") => {
            let address = value(&arguments, "--address")?.parse()?;
            let bytes = value(&arguments, "--bytes")?.parse()?;
            let timeout_ms = value_or(&arguments, "--timeout-ms", "10000").parse()?;
            let min_elapsed_ms = value_or(&arguments, "--min-elapsed-ms", "0").parse()?;
            Ok(transfer(address, bytes, timeout_ms, min_elapsed_ms))
        }
        Some("upload") => {
            let address = value(&arguments, "--address")?.parse()?;
            let bytes = value(&arguments, "--bytes")?.parse()?;
            let timeout_ms = value_or(&arguments, "--timeout-ms", "10000").parse()?;
            let min_elapsed_ms = value_or(&arguments, "--min-elapsed-ms", "0").parse()?;
            Ok(upload(address, bytes, timeout_ms, min_elapsed_ms))
        }
        _ => Err(format!("usage: {APPLICATION_NAME} server --bind ADDR | client --address ADDR [--requests N] [--timeout-ms N] [--interval-ms N] [--min-elapsed-ms N] [--min-spread-ms N] [--require-success|--require-failure|--require-mixed] | transfer|upload --address ADDR --bytes N [--timeout-ms N] [--min-elapsed-ms N]").into()),
    }
}

fn value<'a>(
    arguments: &'a [String],
    expected: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    let index = arguments
        .iter()
        .position(|argument| argument == expected)
        .ok_or_else(|| format!("missing {expected}"))?;
    arguments
        .get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {expected}").into())
}

fn value_or<'a>(arguments: &'a [String], expected: &str, default: &'a str) -> &'a str {
    arguments
        .iter()
        .position(|argument| argument == expected)
        .and_then(|index| arguments.get(index + 1))
        .map_or(default, String::as_str)
}

fn serve(address: SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(address)?;
    println!("{APPLICATION_NAME} server listening on {address}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    let _ = reply(stream);
                });
            }
            Err(error) => eprintln!("accept failed: {error}"),
        }
    }
    Ok(())
}

fn reply(stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    let mut request = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut request)?;
    match parse_request(&request)? {
        Some(LabRequest::Ping) => reader.get_mut().write_all(b"pong\n")?,
        Some(LabRequest::Download(bytes)) => {
            io::copy(&mut io::repeat(0).take(bytes), reader.get_mut())?;
        }
        Some(LabRequest::Upload(bytes)) => {
            let received = io::copy(&mut reader.by_ref().take(bytes), &mut io::sink())?;
            if received != bytes {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("upload ended after {received} of {bytes} bytes"),
                ));
            }
            reader.get_mut().write_all(b"done\n")?;
        }
        None => {}
    }
    Ok(())
}

enum LabRequest {
    Ping,
    Download(u64),
    Upload(u64),
}

fn parse_request(request: &str) -> std::io::Result<Option<LabRequest>> {
    let request = request.trim_end();
    if request == "ping" {
        return Ok(Some(LabRequest::Ping));
    }
    let Some((operation, bytes)) = request.split_once(' ') else {
        return Ok(None);
    };
    match operation {
        "bytes" => parse_byte_count(bytes).map(|bytes| Some(LabRequest::Download(bytes))),
        "upload" => parse_byte_count(bytes).map(|bytes| Some(LabRequest::Upload(bytes))),
        _ => Ok(None),
    }
}

fn parse_byte_count(value: &str) -> std::io::Result<u64> {
    value
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid byte count"))
}

struct ClientSpec {
    address: SocketAddr,
    requests: u32,
    timeout: Duration,
    interval: Duration,
    min_elapsed_ms: u128,
    min_spread_ms: u128,
    require_success: bool,
    require_failure: bool,
    require_mixed: bool,
}

impl ClientSpec {
    fn parse(arguments: &[String]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            address: value(arguments, "--address")?.parse()?,
            requests: value_or(arguments, "--requests", "100").parse()?,
            timeout: Duration::from_millis(value_or(arguments, "--timeout-ms", "500").parse()?),
            interval: Duration::from_millis(value_or(arguments, "--interval-ms", "0").parse()?),
            min_elapsed_ms: value_or(arguments, "--min-elapsed-ms", "0").parse()?,
            min_spread_ms: value_or(arguments, "--min-spread-ms", "0").parse()?,
            require_success: has_flag(arguments, "--require-success"),
            require_failure: has_flag(arguments, "--require-failure"),
            require_mixed: has_flag(arguments, "--require-mixed"),
        })
    }

    fn run(&self) -> bool {
        let started = Instant::now();
        let report = (0..self.requests).fold(RequestReport::default(), |report, index| {
            let request_started = Instant::now();
            let success = request_once(self.address, self.timeout);
            let report = report.record(success, request_started.elapsed());
            if !self.interval.is_zero() && index + 1 < self.requests {
                thread::sleep(self.interval);
            }
            report
        });
        report.finish(self, started.elapsed())
    }
}

#[derive(Default)]
struct RequestReport {
    succeeded: u32,
    failed: u32,
    fastest_ms: Option<u128>,
    slowest_ms: u128,
}

impl RequestReport {
    fn record(mut self, success: bool, elapsed: Duration) -> Self {
        if success {
            self.succeeded += 1;
        } else {
            self.failed += 1;
        }
        let elapsed_ms = elapsed.as_millis();
        self.fastest_ms = Some(
            self.fastest_ms
                .map_or(elapsed_ms, |fastest| fastest.min(elapsed_ms)),
        );
        self.slowest_ms = self.slowest_ms.max(elapsed_ms);
        self
    }

    fn finish(&self, spec: &ClientSpec, elapsed: Duration) -> bool {
        let elapsed_ms = elapsed.as_millis();
        let spread_ms = self
            .fastest_ms
            .map_or(0, |fastest| self.slowest_ms.saturating_sub(fastest));
        println!(
            "requests={} succeeded={} failed={} elapsed_ms={elapsed_ms} spread_ms={spread_ms}",
            spec.requests, self.succeeded, self.failed,
        );
        (!spec.require_success || self.failed == 0)
            && (!spec.require_failure || self.failed > 0)
            && (!spec.require_mixed || (self.succeeded > 0 && self.failed > 0))
            && elapsed_ms >= spec.min_elapsed_ms
            && spread_ms >= spec.min_spread_ms
    }
}

fn has_flag(arguments: &[String], expected: &str) -> bool {
    arguments.iter().any(|argument| argument == expected)
}

fn transfer(address: SocketAddr, bytes: u64, timeout_ms: u64, min_elapsed_ms: u128) -> bool {
    let timeout = Duration::from_millis(timeout_ms);
    let started = Instant::now();
    let Ok(mut stream) = TcpStream::connect_timeout(&address, timeout) else {
        return false;
    };
    if stream.set_read_timeout(Some(timeout)).is_err()
        || stream.set_write_timeout(Some(timeout)).is_err()
        || writeln!(stream, "bytes {bytes}").is_err()
    {
        return false;
    }
    let Ok(received) = io::copy(&mut Read::take(&mut stream, bytes), &mut io::sink()) else {
        return false;
    };
    if received != bytes {
        return false;
    }
    let elapsed_ms = started.elapsed().as_millis();
    println!("bytes={bytes} received={received} elapsed_ms={elapsed_ms}");
    elapsed_ms >= min_elapsed_ms
}

fn upload(address: SocketAddr, bytes: u64, timeout_ms: u64, min_elapsed_ms: u128) -> bool {
    let timeout = Duration::from_millis(timeout_ms);
    let started = Instant::now();
    let Ok(mut stream) = TcpStream::connect_timeout(&address, timeout) else {
        return false;
    };
    if stream.set_read_timeout(Some(timeout)).is_err()
        || stream.set_write_timeout(Some(timeout)).is_err()
        || writeln!(stream, "upload {bytes}").is_err()
    {
        return false;
    }
    let Ok(sent) = io::copy(&mut io::repeat(0).take(bytes), &mut stream) else {
        return false;
    };
    let mut response = [0u8; 5];
    if stream.read_exact(&mut response).is_err() || response != *b"done\n" {
        return false;
    }
    let elapsed_ms = started.elapsed().as_millis();
    println!("bytes={bytes} sent={sent} elapsed_ms={elapsed_ms}");
    elapsed_ms >= min_elapsed_ms
}

fn request_once(address: SocketAddr, timeout: Duration) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, timeout) else {
        return false;
    };
    if stream.set_read_timeout(Some(timeout)).is_err()
        || stream.set_write_timeout(Some(timeout)).is_err()
        || stream.write_all(b"ping\n").is_err()
    {
        return false;
    }
    let mut response = [0u8; 5];
    stream.read_exact(&mut response).is_ok() && response == *b"pong\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_and_server_exchange_a_message() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || reply(listener.accept().unwrap().0));

        assert!(request_once(address, Duration::from_secs(1)));
        server.join().unwrap().unwrap();
    }

    #[test]
    fn client_can_transfer_a_larger_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || reply(listener.accept().unwrap().0));

        assert!(transfer(address, 128 * 1024, 1_000, 0));
        server.join().unwrap().unwrap();
    }

    #[test]
    fn client_can_upload_a_larger_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || reply(listener.accept().unwrap().0));

        assert!(upload(address, 128 * 1024, 1_000, 0));
        server.join().unwrap().unwrap();
    }
}
