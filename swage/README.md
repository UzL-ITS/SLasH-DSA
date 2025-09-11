# SWAGE: A Framework for Rowhammer Experiments

WARNING: This documentation is AI-generated and is still under review

SWAGE is a modular and extensible framework written in Rust for crafting, running, and analyzing Rowhammer security experiments. It is designed to provide a flexible environment for security researchers to test the vulnerability of software, with a particular focus on cryptographic libraries, against Rowhammer-induced bit flips.

The name SWAGE is inspired by the blacksmithing tool used to shape metal, reflecting how this framework helps shape memory layouts and apply pressure (hammering) to find security vulnerabilities.

## Architecture

The framework is built around three core abstractions, allowing researchers to easily combine different strategies for memory arrangement, Rowhammer exploitation, and victim analysis.

*   **`Allocator`**: The Allocator's role is to prepare the memory layout for the experiment. It allocates memory for the victim code and attempts to place it in a physically vulnerable location susceptible to Rowhammer attacks. Different allocators implement various strategies for memory placement, such as using huge pages, custom memory mapping, or other techniques to influence the physical memory layout.

*   **`Hammerer`**: The Hammerer is responsible for performing the actual Rowhammer attack. It repeatedly accesses (hammers) specific memory locations (aggressor rows) to induce bit flips in adjacent victim rows. The framework supports different hammering patterns and techniques, which can be implemented as separate Hammerer crates.

*   **`Victim`**: The Victim is the target code or data being tested for vulnerabilities. The framework executes the victim code while the Hammerer is active and provides mechanisms to detect and analyze any resulting faults or bit flips. This allows for testing specific functionalities, such as cryptographic operations, for Rowhammer-induced errors.

## Crate Structure

SWAGE is organized into a workspace of several crates, each providing a piece of the overall functionality.

### Core Components
*   `swage-core`: Defines the core traits and data structures for the `Allocator`, `Hammerer`, and `Victim` components. It provides the backbone of the framework.

### Allocators (`crates/allocators/`)
*   `swage-hugepage`: An allocator that uses huge pages to obtain physically contiguous memory.
*   `swage-mmap`: A basic allocator using `mmap`.
*   `swage-pfn`: An allocator that uses `/proc/self/pagemap` to get the physical page frame number (PFN) of virtual pages.
*   `swage-spoiler`: An allocator based on the "Spoiler" microarchitectural leak to find contiguous memory regions.
*   `swage-coco`: An allocator that uses `CoCo` to find contiguous memory regions.

### Hammerers (`crates/hammerers/`)
*   `swage-blacksmith`: A hammerer based on the Blacksmith fuzzer, which uses complex access patterns to trigger Rowhammer on modern DDR4/DDR5 DRAM.
*   `swage-dev-mem`: A hammerer that uses `/dev/mem` for hammering.
*   `swage-dummy`: A no-op hammerer for testing and baseline measurements.

### Victims (`crates/swage-victim-*`)
*   `swage-victim-dev-memcheck`: A simple victim used to verify that bit flips can be induced in a controlled environment.
*   Other victim crates (e.g., `swage-victim-ossl-slh-dsa`) are designed to test specific cryptographic implementations.

### Binaries and Tools
*   `swage-bin`: Contains command-line tools to run experiments by combining different allocators, hammerers, and victims.
*   `tools/`: A collection of Python scripts and Jupyter notebooks for analyzing the results of Rowhammer experiments, including cryptanalysis of faulted cryptographic outputs.

## Getting Started

To build the framework and its tools, you will need a Rust environment and Python with the required dependencies.

1.  **Build the Rust crates:**
    ```bash
    cargo build --release
    ```

2.  **Install Python dependencies for analysis tools:**
    ```bash
    pip install -r tools/requirements.txt
    ```

## Usage

The main entry point for running a Rowhammer experiment with SWAGE is the `Swage` struct. It is configured and initialized using a builder pattern, which pieces together the three main components: an `Allocator`, a `Hammerer`, and a `Victim`.

The builder allows you to define factories for creating these components, giving you full control over the experiment's setup. Once configured, you can run the experiment and collect the results.

### Example

Here is a conceptual example of how to set up and run an experiment. This example uses a dummy hammerer and a placeholder victim for illustration.

```rust
use swage::{Swage, SwageConfig};
use swage::allocator::Pfn; // Example allocator
use swage::hammerer::DummyHammerer; // Example hammerer
use swage::victim::Victim;
use swage::memory::MemConfiguration;
use std::time::Duration;

// Define your custom victim struct
struct MyVictim;

impl Victim for MyVictim {
    // Implement the Victim trait for your target code
    // ...
}

fn main() -> anyhow::Result<()> {
    // 1. Define the main configuration for the experiment execution.
    let swage_config = SwageConfig {
        timeout: Some(Duration::from_secs(60 * 10)), // Total experiment timeout
        hammering_timeout: Some(Duration::from_secs(60 * 5)), // Net hammering time
        repetitions: Some(1000), // Max number of experiment repetitions
        profiling_rounds: 5,     // Rounds for finding reproducible bit flips
        reproducibility_threshold: 0.8, // Threshold for considering a flip reproducible
    };

    // 2. Create an Allocator.
    // This example uses the PFN allocator, which requires a memory configuration.
    let mem_config = MemConfiguration::default();
    let allocator = Pfn::new(mem_config, None.into());
    let pattern_size = 4096 * 8; // Example pattern size

    // 3. Build the Swage experiment.
    let swage = Swage::builder()
        // Provide an allocator instance.
        .allocator(allocator)
        // Provide a factory to create a hammerer for the profiling phase.
        // This hammerer is used to find vulnerable memory locations.
        .profile_hammerer_factory(|memory| {
            Box::new(DummyHammerer::new(&memory))
        })
        // Provide a factory to create the victim instance.
        // The victim is the code or data you want to attack.
        .victim_factory(|_memory, _profiling_result| {
            Box::new(MyVictim {})
        })
        // Set the memory pattern size.
        .pattern_size(pattern_size)
        // Apply the experiment configuration.
        .config(swage_config)
        .build()?;

    // 4. Run the experiment.
    let experiments = swage.run()?;

    // 5. Process the results.
    // The `run` method returns a vector of `ExperimentData`, containing
    // information about each experimental run, including any errors or
    // successful outcomes from the victim.
    for result in experiments {
        if let Some(victim_output) = result.victim_data {
            println!("Victim produced output: {:?}", victim_output);
        }
    }

    Ok(())
}
```

### Workflow Breakdown

1.  **Configuration (`SwageConfig`)**: This struct holds high-level parameters for the experiment, such as timeouts and the number of repetitions. This allows you to control the overall duration and effort of the Rowhammer attack.

2.  **Allocator**: You instantiate a specific allocator (e.g., `Pfn`, `HugePageAllocator`). The allocator is responsible for acquiring physical memory that will be used for the experiment.

3.  **Builder (`Swage::builder()`)**: The builder assembles the experiment.
    *   `.allocator()`: Takes the instantiated allocator.
    *   `.profile_hammerer_factory()`: A closure that creates a `Hammerer` used during the initial profiling phase to identify bit flips.
    *   `.victim_factory()`: A closure that creates your `Victim`. It receives information from the profiling phase, such as the locations of discovered bit flips, which can be used to initialize the victim's state.
    *   `.config()`: Applies the `SwageConfig`.

4.  **Run (`swage.run()`)**: This method starts the experiment. SWAGE will use the allocator to get memory, run the profiling hammerer to find bit flips, and then repeatedly execute the main hammering loop with the victim until a timeout is reached, a successful attack is reported by the victim, or the repetition limit is exceeded.

5.  **Results**: The `run` method returns a collection of `ExperimentData`, which you can analyze to determine the outcome of your experiment.

