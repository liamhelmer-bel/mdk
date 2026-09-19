//! Process-level root ownership must also cover CLI fallback and daemon startup.
#![cfg(unix)]
use marmot_app::MarmotRootRuntimeLease;
use std::process::Command;

#[test]
fn direct_cli_refuses_an_owned_root_and_recovers_after_release() {
    let home = tempfile::tempdir().unwrap();
    let lease = MarmotRootRuntimeLease::try_acquire(home.path()).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_wn"))
            .env_remove("WN_SOCKET")
            .env_remove("WN_ACCOUNT")
            .env("WN_SECRET_STORE", "file")
            .args([
                "--home",
                home.path().to_str().unwrap(),
                "--json",
                "accounts",
                "list",
            ])
            .output()
            .unwrap()
    };
    let blocked = run();
    assert!(!blocked.status.success());
    assert!(
        String::from_utf8_lossy(&blocked.stdout).contains("already in use"),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert!(!home.path().join("shared.sqlite3").exists());
    // An abandoned implicit daemon socket must not turn fallback into a lease bypass.
    let socket = wn_cli::daemon::default_socket_path(home.path());
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
    let fallback = run();
    assert!(!fallback.status.success());
    assert!(String::from_utf8_lossy(&fallback.stdout).contains("already in use"));
    drop(lease);
    let released = run();
    assert!(
        released.status.success(),
        "{}",
        String::from_utf8_lossy(&released.stderr)
    );
}

#[test]
fn daemon_refuses_owned_root_before_removing_socket_artifacts() {
    let home = tempfile::tempdir().unwrap();
    let _lease = MarmotRootRuntimeLease::try_acquire(home.path()).unwrap();
    let socket = home.path().join("test.sock");
    std::fs::write(&socket, b"preserve existing artifact").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_wnd"))
        .args([
            "--home",
            home.path().to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
            "--discovery-relays",
            "wss://relay.example.com",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("already in use"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(socket).unwrap(),
        b"preserve existing artifact"
    );
}
