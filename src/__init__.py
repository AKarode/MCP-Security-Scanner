"""
MCP Security Scanner

A comprehensive security scanner for Model Context Protocol (MCP) servers.
"""

__version__ = "0.1.0"
__author__ = "MCP Scanner Team"
__email__ = "team@example.com"
__license__ = "MIT"

from .core.types import (
    Analyzer,
    Parser,
    Vulnerability,
    VulnerabilityType,
    Severity,
    ScanResult,
    ScanConfig,
    ParsedFile,
    Location
)

from .core.scanner import ScanEngine
from .core.registry import AnalyzerRegistry, ParserRegistry

__all__ = [
    # Core types
    "Analyzer",
    "Parser", 
    "Vulnerability",
    "VulnerabilityType",
    "Severity",
    "ScanResult",
    "ScanConfig",
    "ParsedFile",
    "Location",
    
    # Core engine
    "ScanEngine",
    
    # Registries
    "AnalyzerRegistry",
    "ParserRegistry",
    
    # Metadata
    "__version__",
    "__author__",
    "__email__",
    "__license__"
]