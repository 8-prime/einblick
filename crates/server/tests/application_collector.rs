//! Exercise the actual same-image child executable and framed IPC, not a mock.
use einblick_core::config::ApplicationConfig;
use std::{
    io::{Read, Write},
    process::{Child, Command, Stdio},
    time::Duration,
};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn child_discovers_parent_socket_and_drops_unrelated_capabilities() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_einblick"))
            .arg("--internal-application-collector")
            .arg(std::process::id().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let config = ApplicationConfig {
        enabled: true,
        proc_root: "/proc".into(),
        ..ApplicationConfig::default()
    };
    let bytes = serde_json::to_vec(&config).unwrap();
    let mut stdin = child.0.stdin.take().unwrap();
    stdin
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stdin.write_all(&bytes).unwrap();
    drop(stdin);
    let mut stdout = child.0.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut length = [0; 4];
        stdout.read_exact(&mut length).unwrap();
        let length = u32::from_be_bytes(length) as usize;
        assert!(length <= 2 * 1024 * 1024);
        let mut bytes = vec![0; length];
        stdout.read_exact(&mut bytes).unwrap();
        sender
            .send(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap())
            .unwrap();
    });
    let snapshot = receiver.recv_timeout(Duration::from_secs(6)).unwrap();
    assert_eq!(snapshot["available"], true);
    assert!(
        snapshot["sockets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|socket| socket["port"] == port
                && socket["owners"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|owner| owner["pid"] == std::process::id()))
    );
    let status = std::fs::read_to_string(format!("/proc/{}/status", child.0.id())).unwrap();
    for label in ["CapEff:", "CapPrm:", "CapInh:"] {
        let line = status.lines().find(|line| line.starts_with(label)).unwrap();
        let caps = u64::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap();
        assert_eq!(
            caps & !((1 << 19) | (1 << 2)),
            0,
            "unexpected collector capabilities: {line}"
        );
    }
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
}
