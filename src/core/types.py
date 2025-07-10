"""
Core type definitions for the MCP Security Scanner.

This module defines the fundamental data structures used throughout the scanner,
including vulnerability representations, file metadata, and analyzer interfaces.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict, Any, Union
from pathlib import Path
import uuid


class VulnerabilityType(Enum):
    """Categories of security vulnerabilities that can be detected."""
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    SECRETS_EXPOSURE = "secrets_exposure"
    PROMPT_INJECTION = "prompt_injection"
    INSECURE_RANDOMNESS = "insecure_randomness"
    MCP_OVERPRIVILEGED = "mcp_overprivileged"
    MCP_DANGEROUS_TOOL = "mcp_dangerous_tool"
    EVAL_INJECTION = "eval_injection"
    TEMPLATE_INJECTION = "template_injection"


class Severity(Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Location:
    """Represents a location in source code."""
    file: Path
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None


@dataclass
class Vulnerability:
    """Represents a security vulnerability found during analysis."""
    id: str
    type: VulnerabilityType
    severity: Severity
    confidence: float  # 0.0 to 1.0
    location: Location
    message: str
    description: str
    remediation: Optional[str] = None
    references: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.id is None:
            self.id = str(uuid.uuid4())
        if self.references is None:
            self.references = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ParsedFile:
    """Represents a parsed source file with its AST and metadata."""
    path: Path
    content: str
    language: str
    ast: Any  # Language-specific AST representation
    size: int
    encoding: str = "utf-8"
    
    @property
    def lines(self) -> List[str]:
        """Get lines of the file content."""
        return self.content.split('\n')


@dataclass
class ScanResult:
    """Results of a security scan."""
    vulnerabilities: List[Vulnerability]
    files_scanned: int
    scan_duration: float
    timestamp: str
    scanner_version: str
    config_used: Dict[str, Any]
    
    @property
    def total_vulnerabilities(self) -> int:
        """Total number of vulnerabilities found."""
        return len(self.vulnerabilities)
    
    @property
    def vulnerabilities_by_severity(self) -> Dict[Severity, int]:
        """Count vulnerabilities by severity level."""
        counts = {severity: 0 for severity in Severity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity] += 1
        return counts


class Analyzer(ABC):
    """Abstract base class for security analyzers."""
    
    @property
    @abstractmethod
    def id(self) -> str:
        """Unique identifier for this analyzer."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this analyzer detects."""
        pass
    
    @property
    @abstractmethod
    def supported_languages(self) -> List[str]:
        """List of programming languages this analyzer supports."""
        pass
    
    @abstractmethod
    def analyze(self, file: ParsedFile) -> List[Vulnerability]:
        """
        Analyze a parsed file for security vulnerabilities.
        
        Args:
            file: The parsed file to analyze
            
        Returns:
            List of vulnerabilities found in the file
        """
        pass
    
    @abstractmethod
    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure the analyzer with settings.
        
        Args:
            config: Configuration dictionary specific to this analyzer
        """
        pass


class Parser(ABC):
    """Abstract base class for source code parsers."""
    
    @property
    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """File extensions this parser can handle."""
        pass
    
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the given file.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if this parser can handle the file
        """
        pass
    
    @abstractmethod
    def parse(self, file_path: Path) -> ParsedFile:
        """
        Parse a source file into a ParsedFile object.
        
        Args:
            file_path: Path to the file to parse
            
        Returns:
            ParsedFile object containing the parsed content and AST
        """
        pass


@dataclass
class ScanConfig:
    """Configuration for a security scan."""
    target_path: Path
    include_patterns: List[str] = None
    exclude_patterns: List[str] = None
    analyzers: List[str] = None  # Analyzer IDs to run
    output_format: str = "json"
    output_file: Optional[Path] = None
    fail_on_severity: Optional[Severity] = None
    max_file_size: int = 10 * 1024 * 1024  # 10MB default
    parallel_jobs: int = 4
    
    def __post_init__(self):
        if self.include_patterns is None:
            self.include_patterns = ["**/*"]
        if self.exclude_patterns is None:
            self.exclude_patterns = [
                "**/.git/**",
                "**/node_modules/**",
                "**/__pycache__/**",
                "**/venv/**",
                "**/.venv/**",
                "**/build/**",
                "**/dist/**"
            ]