# MCP Security Scanner

A security scanner for Model Context Protocol (MCP) servers (currently in early development).

## Current Status

 **This project is in very early development.** Most features are not yet implemented and exist only as architectural placeholders.

### What Works Now
- Basic CLI structure with `scan`, `list-analyzers`, and `validate-config` commands
- Core architecture for analyzers and parsers
- Basic command injection detection patterns (proof of concept)
- Project structure and build configuration

### What's Planned
- File discovery and parsing for Python, JavaScript, TypeScript, and shell scripts
- Security analyzers for common vulnerabilities (command injection, secrets, etc.)
- MCP-specific analyzers for server configurations and tools
- Report generation in multiple formats
- CI/CD integration

## Installation

```bash
# Clone and install from source (only option currently)
git clone https://github.com/example/mcp-scanner.git
cd mcp-scanner
pip install -e .
```

## Usage

```bash
# Basic scan (will not find much yet due to limited implementation)
mcp-scanner scan .

# List available analyzers
mcp-scanner list-analyzers

# Validate configuration
mcp-scanner validate-config
```

## Configuration

Create a `mcp-scanner.yaml` file:

```yaml
target_path: "."
include_patterns:
  - "**/*.py"
  - "**/*.js"
  - "**/*.ts"
exclude_patterns:
  - "**/node_modules/**"
  - "**/__pycache__/**"
analyzers:
  - "command_injection"
output_format: "json"
```

## Architecture

The scanner follows a modular design:

- **File Walker**: Discovers files to scan (not implemented)
- **Parser Layer**: Language-specific parsing (basic structure only)
- **Analysis Engine**: Coordinates security analyzers (basic implementation)
- **Report Builder**: Generates output reports (not implemented)

## Development

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Code formatting
black src/ tests/
isort src/ tests/
```

## Contributing

This project is in early development and contributions are welcome. Check the `IMPLEMENTATION_TIMELINE.md` for planned features and current priorities.

## License

MIT License - see [LICENSE](LICENSE) file for details.