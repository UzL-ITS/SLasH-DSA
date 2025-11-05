# SLasH-DSA

Code accompanying the SLasH-DSA submission. 

## Getting started with SLasH-DSA

To build the project, first make sure that rust stable is installed, for example by using rustup (https://rustup.rs/). You can
then build SLasH-DSA by issuing `cargo build --release`. For cryptanalysis, check out the python scripts and notebooks in tools/. Most
notably, `tools/cryptanalysis_ossl_slhdsa.ipynb` is the notebook used to generate the 

## Swage

You can find the `SWAGE` framework in the `swage/` subdirectory. We are still working on the documentation. Currently, the documentation
consists of (partly) AI-generated READMEs. Stay tuned!

## Attack code

The SLH-DSA specific attack code can be found in `swage-victim-ossl-slh-dsa`. It contains a `SWAGE` module for the `Orchestrator` trait 
in `src/` and a C implementation of an SLH-DSA signing server in `victim/`.
