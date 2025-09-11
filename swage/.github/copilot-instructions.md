# Swage: A Modular Rowhammer Attack Framework

This document provides instructions for AI assistants to effectively contribute to the Swage codebase. Swage is a Rust-based modular framework for conducting end-to-end Rowhammer attacks.

## Core Architecture

The project is a Cargo workspace with a highly modular structure. The core components are:

- **`swage-core`**: This crate is the heart of the framework. It defines the essential traits that govern the behavior of different modules:
    - `swage_core::allocator::Allocator`: For memory allocation strategies.
    - `swage_core::hammerer::Hammering`: For Rowhammer attack implementations.
    - `swage_core::victim::HammerVictim`: For the target application being attacked.
- **`swage-bin`**: Contains the main executable, `hammer`, which parses command-line arguments and orchestrates the attack by composing modules from the other directories. See `swage-bin/src/bin/hammer.rs` for the primary logic.
- **Module Directories**:
    - `allocators/`: Contains different memory allocation strategies, each as a separate crate (e.g., `swage-spoiler`).
    - `hammerers/`: Contains different hammering implementations (e.g., `swage-blacksmith`).
    - `victims/`: Contains different victim applications to be targeted by the attack.

When working on a task, first identify which of these components you need to modify or implement.

## Developer Workflow

### Building and Running

- **Build the project**:
  ```sh
  cargo build --release
  ```
- **Run the main `hammer` binary**:
  ```sh
  cargo run --release --bin=hammer -- [ARGUMENTS]
  ```
  The arguments are critical for defining the attack. Key arguments include:
  - `--alloc-strategy`: e.g., `spoiler`
  - `--hammerer`: e.g., `blacksmith`
  - A subcommand specifying the victim, e.g., `memcheck`.

  Example:
  ```sh
  cargo run --release --bin=hammer -- --alloc-strategy spoiler --hammerer blacksmith memcheck
  ```

### Adding New Modules (Allocators, Hammerers, Victims)

The framework is designed for easy extension. To add a new module (e.g., a new allocator named `swage-my-allocator`):

1.  Create a new crate inside the appropriate directory: `allocators/swage-my-allocator`. The crate name must start with `swage-` and be placed in the appropriate directory for auto-discovery.
2.  In the new crate, implement the corresponding trait from `swage-core` (e.g., `impl Allocator for MyAllocator`).
3.  Run the `update_modules.sh` script. This script automatically discovers new modules and updates the workspace's `Cargo.toml` to include them.
    ```sh
    ./update_modules.sh
    ```
    **Do not manually edit the module dependencies in the root `Cargo.toml`**. The `discover_modules!` macro and this script handle module registration.

## Project Conventions

- **Trait-based Modularity**: Almost all core functionality is abstracted behind traits in `swage-core`. When adding functionality, prefer implementing these traits.
- **Configuration**: The `hammer` binary is configured via command-line arguments and supplementary JSON files in the `config/` directory (e.g., `config/bs-config.json` for the Blacksmith hammerer).
- **Module Discovery**: The custom `discover_modules!` macro is used in `swage-bin/src/bin/hammer.rs` to find and register available modules at compile time. This is why the `update_modules.sh` script is important.

### Key Files and Directories to Reference

- **Core Abstractions**: `swage-core/src/`
- **Main Application Logic**: `swage-bin/src/bin/hammer.rs`
- **Module Implementations**: `allocators/`, `hammerers/`, `victims/`
- **Workspace Definition**: `Cargo.toml`
- **Module Management Script**: `update_modules.sh`
