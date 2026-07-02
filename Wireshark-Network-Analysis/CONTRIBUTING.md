# Contributing to Wireshark Network Analysis Lab

Thank you for your interest in contributing to our network forensics toolkit! We welcome contributions to display filters, automated python scripts, documentation, and dashboard features.

## Developer Quickstart

1. **Fork and Clone** the repository:
   ```bash
   git clone https://github.com/your-username/Wireshark-Network-Analysis.git
   ```

2. **Install Dependecies**:
   ```bash
   cd Wireshark-Network-Analysis
   chmod +x install.sh setup.sh
   ./install.sh
   ./setup.sh
   ```

3. **Verify Existing Tests**:
   Ensure all existing test cases compile perfectly:
   ```bash
   python3 -m unittest discover -s tests/ -p "*_test.py"
   ```

## Development Guidelines

### Bash Scripting
- All scripts must reside in `scripts/` or root level.
- Must be compliant with ShellCheck. Run `shellcheck <script>.sh` before opening PRs.
- Always use `set -euo pipefail` and quote variables securely.

### Python Code
- Strictly follow PEP8.
- Use explicit type annotations for parameters and return types.
- Write descriptive docstrings following PEP257 conventions.
- Add corresponding test cases inside `tests/forensics_test.py` for any new detection features.

## Opening Pull Requests

- Keep your pull requests modular.
- Summarize your changes, stating the exact threat, Wireshark filter, or CLI parameter introduced.
- Confirm all tests pass.
