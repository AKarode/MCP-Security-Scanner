"""
Sample test file for MCP Scanner

This file contains basic tests to validate the project structure
and core functionality.
"""

import pytest
from pathlib import Path

from src.core.types import Severity, VulnerabilityType, ScanConfig
from src.core.scanner import ScanEngine


class TestProjectStructure:
    """Test basic project structure and imports."""
    
    def test_imports_work(self):
        """Test that core imports work correctly."""
        # Test that we can import core components
        from src.core.types import Analyzer, Parser, Vulnerability
        from src.core.scanner import ScanEngine
        from src.core.registry import AnalyzerRegistry, ParserRegistry
        
        # Basic assertion to ensure imports succeeded
        assert Analyzer is not None
        assert Parser is not None
        assert Vulnerability is not None
        assert ScanEngine is not None
        assert AnalyzerRegistry is not None
        assert ParserRegistry is not None
    
    def test_enums_work(self):
        """Test that enums are properly defined."""
        # Test Severity enum
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"
        
        # Test VulnerabilityType enum
        assert VulnerabilityType.COMMAND_INJECTION.value == "command_injection"
        assert VulnerabilityType.SECRETS_EXPOSURE.value == "secrets_exposure"
        assert VulnerabilityType.PROMPT_INJECTION.value == "prompt_injection"


class TestScanConfig:
    """Test ScanConfig functionality."""
    
    def test_scan_config_creation(self):
        """Test creating ScanConfig with default values."""
        config = ScanConfig(target_path=Path("."))
        
        assert config.target_path == Path(".")
        assert config.include_patterns == ["**/*"]
        assert config.exclude_patterns is not None
        assert len(config.exclude_patterns) > 0
        assert config.output_format == "json"
        assert config.parallel_jobs == 4
        assert config.max_file_size == 10 * 1024 * 1024  # 10MB
    
    def test_scan_config_with_custom_values(self):
        """Test creating ScanConfig with custom values."""
        config = ScanConfig(
            target_path=Path("/tmp"),
            include_patterns=["*.py"],
            exclude_patterns=["*.pyc"],
            output_format="html",
            parallel_jobs=8,
            fail_on_severity=Severity.HIGH
        )
        
        assert config.target_path == Path("/tmp")
        assert config.include_patterns == ["*.py"]
        assert config.exclude_patterns == ["*.pyc"]
        assert config.output_format == "html"
        assert config.parallel_jobs == 8
        assert config.fail_on_severity == Severity.HIGH


class TestScanEngine:
    """Test ScanEngine functionality."""
    
    def test_scan_engine_creation(self):
        """Test creating ScanEngine with configuration."""
        config = ScanConfig(target_path=Path("."))
        engine = ScanEngine(config)
        
        assert engine.config == config
        assert engine.analyzer_registry is not None
        assert engine.parser_registry is not None
    
    def test_scan_engine_should_fail_build(self):
        """Test build failure logic."""
        config = ScanConfig(
            target_path=Path("."),
            fail_on_severity=Severity.HIGH
        )
        engine = ScanEngine(config)
        
        # Create a mock scan result
        from src.core.types import ScanResult
        result = ScanResult(
            vulnerabilities=[],
            files_scanned=0,
            scan_duration=0.0,
            timestamp="2024-01-01T00:00:00",
            scanner_version="0.1.0",
            config_used={}
        )
        
        # Should not fail with no vulnerabilities
        assert not engine.should_fail_build(result)


class TestAnalyzerRegistry:
    """Test AnalyzerRegistry functionality."""
    
    def test_analyzer_registry_creation(self):
        """Test creating AnalyzerRegistry."""
        from src.core.registry import AnalyzerRegistry
        
        registry = AnalyzerRegistry()
        assert registry is not None
        assert registry._analyzers == {}
        assert registry._language_map == {}
    
    def test_analyzer_registry_supported_languages(self):
        """Test getting supported languages."""
        from src.core.registry import AnalyzerRegistry
        
        registry = AnalyzerRegistry()
        languages = registry.get_supported_languages()
        
        # Should return a set (even if empty initially)
        assert isinstance(languages, set)


class TestParserRegistry:
    """Test ParserRegistry functionality."""
    
    def test_parser_registry_creation(self):
        """Test creating ParserRegistry."""
        from src.core.registry import ParserRegistry
        
        registry = ParserRegistry()
        assert registry is not None
        assert registry._parsers == {}
        assert registry._extension_map == {}
    
    def test_parser_registry_supported_extensions(self):
        """Test getting supported extensions."""
        from src.core.registry import ParserRegistry
        
        registry = ParserRegistry()
        extensions = registry.get_supported_extensions()
        
        # Should return a set (even if empty initially)
        assert isinstance(extensions, set)


if __name__ == "__main__":
    pytest.main([__file__])