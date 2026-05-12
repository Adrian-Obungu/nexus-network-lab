# Contributing to Nexus Network Lab

Contributions that add topological depth, improve verification coverage, or extend the automation toolchain are welcome. Before opening a pull request, read through the conventions below.

## Philosophy

This project follows a **Build Slow, Build Sure** approach. Every topology added must be reproducible, every verification script must be deterministic, and every piece of documentation must reflect what the lab actually does — not what it is intended to do.

## Adding a New Lab

1. Create a new directory under `labs/` using the naming convention `NN-topic-name/` (e.g., `03-vlan-segmentation/`).
2. Include a `*.clab.yml` topology file, any required node config files, and a `README.md` that documents the objectives, IP addressing table, and step-by-step procedure.
3. Add a corresponding verification script under `scripts/` and register it in the `Makefile`.

## Verification Scripts

- All scripts must use `docker exec` against named Containerlab containers.
- Output must be deterministic — parse structured data where available (e.g., `show ip ospf neighbor json`).
- Use `rich` for terminal output if available; fall back gracefully to plain print.

## Pull Request Process

1. Fork the repository and branch from `main`.
2. Ensure `make verify-01` (or the equivalent for your lab) passes cleanly.
3. Update `README.md` to reflect any new lab or capability.
4. Submit the PR with a clear description of what the topology demonstrates and its forensic or operational value.
