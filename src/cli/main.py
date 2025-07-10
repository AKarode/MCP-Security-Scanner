"""
Command Line Interface for MCP Security Scanner

This module provides the main CLI entry point for the MCP Security Scanner.
It handles command-line argument parsing, configuration loading, and orchestrates
the scanning process.

Usage:
    mcp-scanner scan <path> [options]
    mcp-scanner --help
    mcp-scanner --version

Implementation Notes:
- Should support all configuration options from the implementation guide
- Should provide clear error messages and usage instructions
- Should handle graceful shutdown on interruption
- Should support output to various formats (JSON, HTML, etc.)
"""

import argparse
import sys
import logging
from pathlib import Path
from typing import Optional, List
import json
import signal
import time

from ..core.types import ScanConfig, Severity
from ..core.scanner import ScanEngine
from ..reporting.generators import ReportGenerator
from .config import load_config, ConfigError


logger = logging.getLogger(__name__)


class MCPScanner:
    """
    Main CLI application class for the MCP Security Scanner.
    
    This class handles command-line interface operations, configuration management,
    and coordination of the scanning process.
    """
    
    def __init__(self):
        """Initialize the MCP Scanner CLI."""
        self.interrupted = False
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            logger.info("Received interrupt signal, shutting down gracefully...")
            self.interrupted = True
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def main(self, argv: Optional[List[str]] = None) -> int:
        """
        Main entry point for the CLI application.
        
        Args:
            argv: Command line arguments (uses sys.argv if None)
            
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Parse command line arguments
            args = self._parse_args(argv)
            
            # Setup logging
            self._setup_logging(args.verbose, args.quiet)
            
            # Load configuration
            config = self._load_configuration(args)
            
            # Execute the appropriate command
            if args.command == "scan":
                return self._execute_scan(config)
            elif args.command == "list-analyzers":
                return self._list_analyzers()
            elif args.command == "validate-config":
                return self._validate_config(config)
            else:
                logger.error(f"Unknown command: {args.command}")
                return 1
                
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            return 130
        except ConfigError as e:
            logger.error(f"Configuration error: {e}")
            return 1
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception("Full traceback:")
            return 1
    
    def _parse_args(self, argv: Optional[List[str]] = None) -> argparse.Namespace:
        """
        Parse command line arguments.
        
        Args:
            argv: Command line arguments to parse
            
        Returns:
            Parsed arguments namespace
            
        Implementation Notes:
        - Should support all configuration options from the requirements
        - Should provide clear help text and examples
        - Should validate argument combinations
        - Should support both short and long option forms
        """
        parser = argparse.ArgumentParser(
            description="MCP Security Scanner - Find security vulnerabilities in MCP server code",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  mcp-scanner scan ./my-mcp-server
  mcp-scanner scan . --output-format html --output-file report.html
  mcp-scanner scan . --fail-on-severity high --analyzers secrets,command_injection
  mcp-scanner scan . --config mcp-scanner.yaml
            """
        )
        
        parser.add_argument(
            "--version",
            action="version",
            version="MCP Scanner 0.1.0"  # TODO: Get from package metadata
        )
        
        # Global options
        parser.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="Enable verbose logging"
        )
        
        parser.add_argument(
            "-q", "--quiet",
            action="store_true",
            help="Suppress all output except errors"
        )
        
        parser.add_argument(
            "--config",
            type=Path,
            help="Path to configuration file"
        )
        
        # Create subparsers for different commands
        subparsers = parser.add_subparsers(dest="command", help="Available commands")
        
        # Scan command
        scan_parser = subparsers.add_parser("scan", help="Scan a directory for security issues")
        scan_parser.add_argument(
            "target",
            type=Path,
            help="Path to scan for security issues"
        )
        
        scan_parser.add_argument(
            "--include",
            action="append",
            default=[],
            help="Include patterns (can be specified multiple times)"
        )
        
        scan_parser.add_argument(
            "--exclude",
            action="append",
            default=[],
            help="Exclude patterns (can be specified multiple times)"
        )
        
        scan_parser.add_argument(
            "--analyzers",
            help="Comma-separated list of analyzers to run"
        )
        
        scan_parser.add_argument(
            "--output-format",
            choices=["json", "html", "markdown", "text"],
            default="json",
            help="Output format for the report"
        )
        
        scan_parser.add_argument(
            "--output-file", "-o",
            type=Path,
            help="Output file for the report"
        )
        
        scan_parser.add_argument(
            "--fail-on-severity",
            choices=["critical", "high", "medium", "low", "info"],
            help="Fail with non-zero exit code if vulnerabilities of this severity or higher are found"
        )
        
        scan_parser.add_argument(
            "--max-file-size",
            type=int,
            default=10 * 1024 * 1024,  # 10MB
            help="Maximum file size to scan in bytes"
        )
        
        scan_parser.add_argument(
            "--parallel-jobs", "-j",
            type=int,
            default=4,
            help="Number of parallel jobs for scanning"
        )
        
        # List analyzers command
        list_parser = subparsers.add_parser("list-analyzers", help="List available analyzers")
        
        # Validate config command
        validate_parser = subparsers.add_parser("validate-config", help="Validate configuration file")
        
        args = parser.parse_args(argv)
        
        # Set default command if none specified
        if args.command is None:
            parser.print_help()
            sys.exit(1)
        
        return args
    
    def _setup_logging(self, verbose: bool, quiet: bool) -> None:
        """
        Configure logging based on verbosity settings.
        
        Args:
            verbose: Enable verbose logging
            quiet: Suppress all output except errors
        """
        if quiet:
            level = logging.ERROR
        elif verbose:
            level = logging.DEBUG
        else:
            level = logging.INFO
        
        logging.basicConfig(
            level=level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    
    def _load_configuration(self, args: argparse.Namespace) -> ScanConfig:
        """
        Load and merge configuration from file and command line arguments.
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            Merged scan configuration
            
        Implementation Notes:
        - Should load from config file if specified
        - Should override config file settings with command line arguments
        - Should validate configuration consistency
        - Should provide clear error messages for invalid configurations
        """
        # Start with default configuration
        config = ScanConfig(target_path=Path.cwd())
        
        # Load from configuration file if specified
        if args.config:
            file_config = load_config(args.config)
            # TODO: Merge file configuration with defaults
            logger.info(f"Loaded configuration from {args.config}")
        
        # Override with command line arguments
        if hasattr(args, 'target') and args.target:
            config.target_path = args.target
        
        if hasattr(args, 'include') and args.include:
            config.include_patterns = args.include
        
        if hasattr(args, 'exclude') and args.exclude:
            config.exclude_patterns.extend(args.exclude)
        
        if hasattr(args, 'analyzers') and args.analyzers:
            config.analyzers = args.analyzers.split(',')
        
        if hasattr(args, 'output_format') and args.output_format:
            config.output_format = args.output_format
        
        if hasattr(args, 'output_file') and args.output_file:
            config.output_file = args.output_file
        
        if hasattr(args, 'fail_on_severity') and args.fail_on_severity:
            config.fail_on_severity = Severity(args.fail_on_severity)
        
        if hasattr(args, 'max_file_size') and args.max_file_size:
            config.max_file_size = args.max_file_size
        
        if hasattr(args, 'parallel_jobs') and args.parallel_jobs:
            config.parallel_jobs = args.parallel_jobs
        
        return config
    
    def _execute_scan(self, config: ScanConfig) -> int:
        """
        Execute the security scan.
        
        Args:
            config: Scan configuration
            
        Returns:
            Exit code (0 for success, non-zero for failure)
            
        Implementation Notes:
        - Should create and configure the scan engine
        - Should handle scan interruption gracefully
        - Should generate reports in the specified format
        - Should return appropriate exit codes based on findings
        """
        logger.info(f"Starting security scan of {config.target_path}")
        
        # Validate target path
        if not config.target_path.exists():
            logger.error(f"Target path does not exist: {config.target_path}")
            return 1
        
        # Create and configure the scan engine
        engine = ScanEngine(config)
        
        # Execute the scan
        start_time = time.time()
        try:
            result = engine.scan()
            
            if self.interrupted:
                logger.warning("Scan was interrupted")
                return 130
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return 1
        
        # Generate and output the report
        try:
            report_generator = ReportGenerator(config.output_format)
            report_content = report_generator.generate(result)
            
            if config.output_file:
                config.output_file.write_text(report_content)
                logger.info(f"Report written to {config.output_file}")
            else:
                print(report_content)
                
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return 1
        
        # Log scan summary
        scan_duration = time.time() - start_time
        logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        logger.info(f"Found {result.total_vulnerabilities} vulnerabilities in {result.files_scanned} files")
        
        # Print severity breakdown
        severity_counts = result.vulnerabilities_by_severity
        for severity, count in severity_counts.items():
            if count > 0:
                logger.info(f"  {severity.value}: {count}")
        
        # Determine exit code based on findings
        if engine.should_fail_build(result):
            logger.error("Build failure criteria met")
            return 1
        
        return 0
    
    def _list_analyzers(self) -> int:
        """
        List available analyzers.
        
        Returns:
            Exit code (always 0 for success)
            
        Implementation Notes:
        - Should discover and list all available analyzers
        - Should show analyzer descriptions and supported languages
        - Should provide information about analyzer capabilities
        """
        # TODO: Implement analyzer discovery and listing
        # - Get all registered analyzers
        # - Format analyzer information nicely
        # - Show supported languages and capabilities
        
        from ..core.registry import AnalyzerRegistry
        
        registry = AnalyzerRegistry()
        analyzers = registry.list_analyzers()
        
        print("Available Analyzers:")
        print("=" * 40)
        
        for analyzer in analyzers:
            print(f"ID: {analyzer.id}")
            print(f"Description: {analyzer.description}")
            print(f"Languages: {', '.join(analyzer.supported_languages)}")
            print("-" * 40)
        
        if not analyzers:
            print("No analyzers found. This might indicate a configuration issue.")
            return 1
        
        return 0
    
    def _validate_config(self, config: ScanConfig) -> int:
        """
        Validate the configuration file.
        
        Args:
            config: Configuration to validate
            
        Returns:
            Exit code (0 for valid, 1 for invalid)
            
        Implementation Notes:
        - Should check all configuration values for validity
        - Should provide detailed error messages for invalid settings
        - Should verify referenced files and paths exist
        - Should validate analyzer and parser availability
        """
        # TODO: Implement comprehensive configuration validation
        # - Check all paths exist and are accessible
        # - Validate analyzer names against available analyzers
        # - Check configuration value ranges and types
        # - Verify output format and file write permissions
        
        logger.info("Validating configuration...")
        
        # Basic validation
        if not config.target_path.exists():
            logger.error(f"Target path does not exist: {config.target_path}")
            return 1
        
        if config.output_file and not config.output_file.parent.exists():
            logger.error(f"Output directory does not exist: {config.output_file.parent}")
            return 1
        
        logger.info("Configuration is valid")
        return 0


def main():
    """Entry point for the CLI application."""
    scanner = MCPScanner()
    sys.exit(scanner.main())


if __name__ == "__main__":
    main()