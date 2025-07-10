"""
Core scanner engine that orchestrates the security analysis process.

This module contains the main ScanEngine class that coordinates file discovery,
parsing, analysis, and reporting.
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
import time
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from .types import (
    Analyzer, Parser, ScanConfig, ScanResult, 
    ParsedFile, Vulnerability, Severity
)
from .registry import AnalyzerRegistry, ParserRegistry


logger = logging.getLogger(__name__)


class ScanEngine:
    """
    Main engine that coordinates the security scanning process.
    
    The ScanEngine follows this workflow:
    1. Discover files in the target directory
    2. Parse files using appropriate parsers
    3. Run analyzers on parsed files
    4. Collect and aggregate results
    5. Generate reports
    """
    
    def __init__(self, config: ScanConfig):
        """
        Initialize the scan engine with configuration.
        
        Args:
            config: Scan configuration specifying targets and options
        """
        self.config = config
        self.analyzer_registry = AnalyzerRegistry()
        self.parser_registry = ParserRegistry()
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configure logging for the scan engine."""
        # TODO: Set up structured logging with appropriate levels
        # Should respect config.verbose flag when implemented
        pass
    
    def discover_files(self) -> List[Path]:
        """
        Discover files to scan based on configuration patterns.
        
        Returns:
            List of file paths to scan
            
        Implementation Notes:
        - Should respect include/exclude patterns from config
        - Should handle symlinks appropriately
        - Should respect max_file_size limits
        - Should be efficient for large repositories
        """
        # TODO: Implement file discovery logic
        # - Use pathlib.Path.glob() or similar for pattern matching
        # - Filter by size, check if files are readable
        # - Log discovered file counts by type
        discovered_files = []
        
        logger.info(f"Discovering files in {self.config.target_path}")
        logger.info(f"Found {len(discovered_files)} files to scan")
        
        return discovered_files
    
    def parse_file(self, file_path: Path) -> Optional[ParsedFile]:
        """
        Parse a single file using the appropriate parser.
        
        Args:
            file_path: Path to the file to parse
            
        Returns:
            ParsedFile if parsing succeeds, None otherwise
            
        Implementation Notes:
        - Should select parser based on file extension
        - Should handle parse errors gracefully
        - Should include file metadata (size, encoding, etc.)
        """
        # TODO: Implement file parsing logic
        # - Get appropriate parser from registry
        # - Handle encoding detection
        # - Catch and log parse errors
        # - Return None for unparseable files
        
        try:
            parser = self.parser_registry.get_parser_for_file(file_path)
            if parser is None:
                logger.debug(f"No parser available for {file_path}")
                return None
            
            return parser.parse(file_path)
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
            return None
    
    def analyze_file(self, parsed_file: ParsedFile) -> List[Vulnerability]:
        """
        Run all applicable analyzers on a parsed file.
        
        Args:
            parsed_file: The parsed file to analyze
            
        Returns:
            List of vulnerabilities found in the file
            
        Implementation Notes:
        - Should run only analyzers that support the file's language
        - Should handle analyzer errors gracefully
        - Should merge results from multiple analyzers
        - Should apply confidence filtering if configured
        """
        # TODO: Implement analysis orchestration
        # - Get analyzers for file language from registry
        # - Run each analyzer and collect results
        # - Filter results by confidence threshold
        # - Log analysis progress and errors
        
        vulnerabilities = []
        applicable_analyzers = self.analyzer_registry.get_analyzers_for_language(
            parsed_file.language
        )
        
        for analyzer in applicable_analyzers:
            try:
                results = analyzer.analyze(parsed_file)
                vulnerabilities.extend(results)
                logger.debug(f"Analyzer {analyzer.id} found {len(results)} issues in {parsed_file.path}")
            except Exception as e:
                logger.error(f"Analyzer {analyzer.id} failed on {parsed_file.path}: {e}")
        
        return vulnerabilities
    
    def scan(self) -> ScanResult:
        """
        Execute the complete security scan.
        
        Returns:
            ScanResult containing all findings and metadata
            
        Implementation Notes:
        - Should support parallel processing when configured
        - Should provide progress feedback for long scans
        - Should handle interruption gracefully
        - Should collect timing and performance metrics
        """
        start_time = time.time()
        all_vulnerabilities = []
        files_scanned = 0
        
        logger.info(f"Starting security scan of {self.config.target_path}")
        
        # Discover files to scan
        files_to_scan = self.discover_files()
        
        # Process files (potentially in parallel)
        if self.config.parallel_jobs > 1:
            vulnerabilities = self._scan_parallel(files_to_scan)
        else:
            vulnerabilities = self._scan_sequential(files_to_scan)
        
        all_vulnerabilities.extend(vulnerabilities)
        files_scanned = len(files_to_scan)
        
        scan_duration = time.time() - start_time
        
        result = ScanResult(
            vulnerabilities=all_vulnerabilities,
            files_scanned=files_scanned,
            scan_duration=scan_duration,
            timestamp=datetime.now().isoformat(),
            scanner_version="0.1.0",  # TODO: Get from package metadata
            config_used=self._serialize_config()
        )
        
        logger.info(f"Scan completed in {scan_duration:.2f}s")
        logger.info(f"Found {len(all_vulnerabilities)} vulnerabilities in {files_scanned} files")
        
        return result
    
    def _scan_sequential(self, files: List[Path]) -> List[Vulnerability]:
        """Scan files sequentially."""
        # TODO: Implement sequential scanning
        # - Parse each file
        # - Run analyzers on each parsed file
        # - Collect all vulnerabilities
        # - Log progress periodically
        
        vulnerabilities = []
        for file_path in files:
            parsed_file = self.parse_file(file_path)
            if parsed_file:
                file_vulnerabilities = self.analyze_file(parsed_file)
                vulnerabilities.extend(file_vulnerabilities)
        
        return vulnerabilities
    
    def _scan_parallel(self, files: List[Path]) -> List[Vulnerability]:
        """Scan files in parallel using ThreadPoolExecutor."""
        # TODO: Implement parallel scanning
        # - Use ThreadPoolExecutor with config.parallel_jobs
        # - Handle thread-safety for shared resources
        # - Collect results from all threads
        # - Maintain progress tracking across threads
        
        vulnerabilities = []
        
        with ThreadPoolExecutor(max_workers=self.config.parallel_jobs) as executor:
            # Submit all files for processing
            future_to_file = {
                executor.submit(self._process_file, file_path): file_path
                for file_path in files
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_vulnerabilities = future.result()
                    vulnerabilities.extend(file_vulnerabilities)
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")
        
        return vulnerabilities
    
    def _process_file(self, file_path: Path) -> List[Vulnerability]:
        """Process a single file (parse + analyze)."""
        parsed_file = self.parse_file(file_path)
        if parsed_file:
            return self.analyze_file(parsed_file)
        return []
    
    def _serialize_config(self) -> Dict[str, Any]:
        """Serialize scan configuration for result metadata."""
        # TODO: Convert ScanConfig to dictionary
        # - Handle Path objects (convert to strings)
        # - Include only relevant configuration
        # - Exclude sensitive information
        
        return {
            "target_path": str(self.config.target_path),
            "include_patterns": self.config.include_patterns,
            "exclude_patterns": self.config.exclude_patterns,
            "analyzers": self.config.analyzers,
            "parallel_jobs": self.config.parallel_jobs,
            "max_file_size": self.config.max_file_size
        }
    
    def should_fail_build(self, result: ScanResult) -> bool:
        """
        Determine if the scan results should fail the build.
        
        Args:
            result: The scan result to evaluate
            
        Returns:
            True if the build should fail based on configuration
            
        Implementation Notes:
        - Should respect config.fail_on_severity setting
        - Should consider confidence thresholds
        - Should provide clear reasoning for failure
        """
        if self.config.fail_on_severity is None:
            return False
        
        # TODO: Implement severity-based failure logic
        # - Check if any vulnerabilities meet the failure criteria
        # - Consider confidence levels in the decision
        # - Log the reason for build failure
        
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        fail_threshold = severity_order.index(self.config.fail_on_severity)
        
        for vulnerability in result.vulnerabilities:
            vuln_severity_index = severity_order.index(vulnerability.severity)
            if vuln_severity_index <= fail_threshold:
                logger.warning(f"Build failure triggered by {vulnerability.severity.value} vulnerability")
                return True
        
        return False