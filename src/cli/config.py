"""
Configuration loading and validation for the MCP Scanner CLI.

This module handles loading configuration from various sources (files, environment variables)
and merging them with command-line arguments to create a complete configuration.

Supported configuration formats:
- YAML (.yaml, .yml)
- JSON (.json)
- TOML (.toml)

Configuration precedence (highest to lowest):
1. Command-line arguments
2. Environment variables
3. Configuration file
4. Default values
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging

from ..core.types import ScanConfig, Severity


logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Exception raised for configuration-related errors."""
    pass


class ConfigLoader:
    """
    Configuration loader that handles multiple configuration sources.
    
    This class provides methods to load configuration from files, environment variables,
    and merge them appropriately.
    """
    
    def __init__(self):
        """Initialize the configuration loader."""
        self.env_prefix = "MCP_SCANNER_"
    
    def load_from_file(self, config_path: Path) -> Dict[str, Any]:
        """
        Load configuration from a file.
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            Configuration dictionary
            
        Raises:
            ConfigError: If the file cannot be loaded or parsed
            
        Implementation Notes:
        - Should support YAML, JSON, and TOML formats
        - Should detect format from file extension
        - Should provide clear error messages for parsing failures
        - Should validate basic configuration structure
        """
        if not config_path.exists():
            raise ConfigError(f"Configuration file not found: {config_path}")
        
        try:
            content = config_path.read_text()
            
            if config_path.suffix.lower() == '.json':
                return json.loads(content)
            elif config_path.suffix.lower() in ['.yaml', '.yml']:
                return yaml.safe_load(content) or {}
            elif config_path.suffix.lower() == '.toml':
                # TODO: Add TOML support
                try:
                    import tomllib
                    return tomllib.loads(content)
                except ImportError:
                    raise ConfigError("TOML support requires Python 3.11+ or tomli package")
            else:
                raise ConfigError(f"Unsupported configuration file format: {config_path.suffix}")
                
        except Exception as e:
            raise ConfigError(f"Failed to parse configuration file {config_path}: {e}")
    
    def load_from_env(self) -> Dict[str, Any]:
        """
        Load configuration from environment variables.
        
        Returns:
            Configuration dictionary from environment variables
            
        Implementation Notes:
        - Should use a consistent naming convention (MCP_SCANNER_*)
        - Should support all major configuration options
        - Should handle type conversion appropriately
        - Should provide clear documentation of environment variables
        """
        config = {}
        
        # TODO: Implement comprehensive environment variable loading
        # - Map environment variables to configuration keys
        # - Handle type conversion (string -> int, bool, etc.)
        # - Support complex types like lists and dictionaries
        # - Document all supported environment variables
        
        env_mappings = {
            f"{self.env_prefix}TARGET_PATH": "target_path",
            f"{self.env_prefix}OUTPUT_FORMAT": "output_format",
            f"{self.env_prefix}OUTPUT_FILE": "output_file",
            f"{self.env_prefix}FAIL_ON_SEVERITY": "fail_on_severity",
            f"{self.env_prefix}MAX_FILE_SIZE": "max_file_size",
            f"{self.env_prefix}PARALLEL_JOBS": "parallel_jobs",
            f"{self.env_prefix}ANALYZERS": "analyzers"
        }
        
        for env_var, config_key in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                config[config_key] = self._convert_env_value(config_key, value)
        
        # Handle list-type environment variables
        include_patterns = os.environ.get(f"{self.env_prefix}INCLUDE_PATTERNS")
        if include_patterns:
            config["include_patterns"] = include_patterns.split(',')
        
        exclude_patterns = os.environ.get(f"{self.env_prefix}EXCLUDE_PATTERNS")
        if exclude_patterns:
            config["exclude_patterns"] = exclude_patterns.split(',')
        
        return config
    
    def _convert_env_value(self, key: str, value: str) -> Any:
        """
        Convert environment variable string value to appropriate type.
        
        Args:
            key: Configuration key name
            value: String value from environment
            
        Returns:
            Converted value
        """
        # Integer conversions
        if key in ["max_file_size", "parallel_jobs"]:
            try:
                return int(value)
            except ValueError:
                raise ConfigError(f"Invalid integer value for {key}: {value}")
        
        # Boolean conversions
        if key in ["verbose", "quiet", "debug"]:
            return value.lower() in ["true", "1", "yes", "on"]
        
        # Path conversions
        if key in ["target_path", "output_file"]:
            return Path(value)
        
        # Severity enum conversion
        if key == "fail_on_severity":
            try:
                return Severity(value.lower())
            except ValueError:
                raise ConfigError(f"Invalid severity value: {value}")
        
        # List conversions
        if key == "analyzers":
            return value.split(',')
        
        # Default: return as string
        return value
    
    def merge_configs(self, *configs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge multiple configuration dictionaries.
        
        Args:
            *configs: Configuration dictionaries to merge (in order of precedence)
            
        Returns:
            Merged configuration dictionary
            
        Implementation Notes:
        - Should handle nested dictionaries appropriately
        - Should preserve list values without merging
        - Should give precedence to later configurations
        - Should handle type conflicts gracefully
        """
        merged = {}
        
        for config in configs:
            if config:
                merged.update(config)
        
        return merged
    
    def validate_config(self, config: Dict[str, Any]) -> None:
        """
        Validate a configuration dictionary.
        
        Args:
            config: Configuration dictionary to validate
            
        Raises:
            ConfigError: If the configuration is invalid
            
        Implementation Notes:
        - Should check required fields are present
        - Should validate value types and ranges
        - Should check file paths exist
        - Should validate analyzer names
        """
        # TODO: Implement comprehensive configuration validation
        # - Check required fields
        # - Validate value types and ranges
        # - Check file and directory paths
        # - Validate analyzer and parser names
        
        # Basic validation
        if "target_path" in config:
            target_path = Path(config["target_path"])
            if not target_path.exists():
                raise ConfigError(f"Target path does not exist: {target_path}")
        
        if "parallel_jobs" in config:
            jobs = config["parallel_jobs"]
            if not isinstance(jobs, int) or jobs < 1:
                raise ConfigError(f"parallel_jobs must be a positive integer, got: {jobs}")
        
        if "max_file_size" in config:
            size = config["max_file_size"]
            if not isinstance(size, int) or size < 0:
                raise ConfigError(f"max_file_size must be a non-negative integer, got: {size}")


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load configuration from file and environment variables.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        Loaded configuration dictionary
        
    Raises:
        ConfigError: If configuration loading fails
        
    Implementation Notes:
    - Should search for default configuration files if none specified
    - Should merge file and environment configurations
    - Should validate the final configuration
    - Should provide clear error messages for issues
    """
    loader = ConfigLoader()
    
    # Load from file if specified
    file_config = {}
    if config_path:
        file_config = loader.load_from_file(config_path)
    else:
        # Search for default configuration files
        default_config_files = [
            Path("mcp-scanner.yaml"),
            Path("mcp-scanner.yml"),
            Path("mcp-scanner.json"),
            Path(".mcp-scanner.yaml"),
            Path(".mcp-scanner.yml"),
            Path(".mcp-scanner.json")
        ]
        
        for config_file in default_config_files:
            if config_file.exists():
                logger.info(f"Found default configuration file: {config_file}")
                file_config = loader.load_from_file(config_file)
                break
    
    # Load from environment variables
    env_config = loader.load_from_env()
    
    # Merge configurations (env overrides file)
    merged_config = loader.merge_configs(file_config, env_config)
    
    # Validate the final configuration
    loader.validate_config(merged_config)
    
    return merged_config


def create_default_config() -> Dict[str, Any]:
    """
    Create a default configuration dictionary.
    
    Returns:
        Default configuration dictionary
        
    Implementation Notes:
    - Should include all configurable options with sensible defaults
    - Should be suitable for most common use cases
    - Should be well-documented
    """
    return {
        "target_path": ".",
        "include_patterns": ["**/*"],
        "exclude_patterns": [
            "**/.git/**",
            "**/node_modules/**",
            "**/__pycache__/**",
            "**/venv/**",
            "**/.venv/**",
            "**/build/**",
            "**/dist/**",
            "**/.pytest_cache/**",
            "**/coverage/**",
            "**/*.min.js",
            "**/*.min.css"
        ],
        "analyzers": None,  # None means all available analyzers
        "output_format": "json",
        "output_file": None,
        "fail_on_severity": None,
        "max_file_size": 10 * 1024 * 1024,  # 10MB
        "parallel_jobs": 4,
        "analyzer_configs": {
            "secrets_detection": {
                "entropy_threshold": 4.5,
                "min_secret_length": 8,
                "confidence_threshold": 0.6
            },
            "command_injection": {
                "confidence_threshold": 0.7
            },
            "mcp_permissions": {
                "min_privilege_mode": True
            }
        }
    }


def save_config(config: Dict[str, Any], config_path: Path) -> None:
    """
    Save configuration to a file.
    
    Args:
        config: Configuration dictionary to save
        config_path: Path where to save the configuration
        
    Raises:
        ConfigError: If saving fails
        
    Implementation Notes:
    - Should detect output format from file extension
    - Should format the output nicely
    - Should handle write permissions and errors
    - Should validate the configuration before saving
    """
    try:
        if config_path.suffix.lower() == '.json':
            content = json.dumps(config, indent=2, default=str)
        elif config_path.suffix.lower() in ['.yaml', '.yml']:
            content = yaml.dump(config, default_flow_style=False, sort_keys=False)
        else:
            raise ConfigError(f"Unsupported configuration file format: {config_path.suffix}")
        
        config_path.write_text(content)
        logger.info(f"Configuration saved to {config_path}")
        
    except Exception as e:
        raise ConfigError(f"Failed to save configuration to {config_path}: {e}")