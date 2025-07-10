"""
Registry systems for managing analyzers and parsers.

This module provides centralized registration and discovery of analyzer and parser plugins,
enabling extensible architecture for the security scanner.
"""

from typing import Dict, List, Optional, Set
from pathlib import Path
import logging
from abc import ABC, abstractmethod

from .types import Analyzer, Parser


logger = logging.getLogger(__name__)


class AnalyzerRegistry:
    """
    Registry for managing security analyzers.
    
    The registry provides:
    - Discovery of available analyzers
    - Registration of new analyzers
    - Lookup by language or capability
    - Configuration management
    """
    
    def __init__(self):
        """Initialize the analyzer registry."""
        self._analyzers: Dict[str, Analyzer] = {}
        self._language_map: Dict[str, Set[str]] = {}
        self._initialized = False
    
    def register(self, analyzer: Analyzer) -> None:
        """
        Register a new analyzer.
        
        Args:
            analyzer: The analyzer instance to register
            
        Implementation Notes:
        - Should validate analyzer interface compliance
        - Should handle duplicate registration gracefully
        - Should update language mappings
        """
        if analyzer.id in self._analyzers:
            logger.warning(f"Analyzer {analyzer.id} already registered, overwriting")
        
        self._analyzers[analyzer.id] = analyzer
        
        # Update language mappings
        for language in analyzer.supported_languages:
            if language not in self._language_map:
                self._language_map[language] = set()
            self._language_map[language].add(analyzer.id)
        
        logger.debug(f"Registered analyzer: {analyzer.id}")
    
    def get_analyzer(self, analyzer_id: str) -> Optional[Analyzer]:
        """
        Get an analyzer by its ID.
        
        Args:
            analyzer_id: Unique identifier for the analyzer
            
        Returns:
            The analyzer instance or None if not found
        """
        return self._analyzers.get(analyzer_id)
    
    def get_analyzers_for_language(self, language: str) -> List[Analyzer]:
        """
        Get all analyzers that support a specific language.
        
        Args:
            language: Programming language identifier
            
        Returns:
            List of analyzers that support the language
            
        Implementation Notes:
        - Should handle case-insensitive language matching
        - Should return empty list for unsupported languages
        - Should maintain consistent ordering
        """
        if not self._initialized:
            self._load_default_analyzers()
        
        analyzer_ids = self._language_map.get(language.lower(), set())
        return [self._analyzers[aid] for aid in analyzer_ids if aid in self._analyzers]
    
    def list_analyzers(self) -> List[Analyzer]:
        """
        Get all registered analyzers.
        
        Returns:
            List of all registered analyzer instances
        """
        if not self._initialized:
            self._load_default_analyzers()
        
        return list(self._analyzers.values())
    
    def get_supported_languages(self) -> Set[str]:
        """
        Get all languages supported by registered analyzers.
        
        Returns:
            Set of supported language identifiers
        """
        return set(self._language_map.keys())
    
    def _load_default_analyzers(self) -> None:
        """
        Load default analyzers that come with the scanner.
        
        Implementation Notes:
        - Should discover analyzers from the analyzers package
        - Should handle import errors gracefully
        - Should log successful/failed analyzer loads
        - Should support plugin discovery from external packages
        """
        # TODO: Implement analyzer discovery and loading
        # - Import all analyzer modules from src.analyzers
        # - Instantiate analyzer classes
        # - Register each analyzer
        # - Handle configuration loading
        
        logger.info("Loading default analyzers...")
        
        # Placeholder for actual analyzer loading
        # This would typically involve dynamic imports:
        # from ..analyzers import command_injection, secrets_detection, etc.
        # self.register(command_injection.CommandInjectionAnalyzer())
        # self.register(secrets_detection.SecretsAnalyzer())
        
        self._initialized = True
        logger.info(f"Loaded {len(self._analyzers)} analyzers")


class ParserRegistry:
    """
    Registry for managing source code parsers.
    
    The registry provides:
    - Discovery of available parsers
    - Registration of new parsers
    - Lookup by file extension or language
    - Parser capability detection
    """
    
    def __init__(self):
        """Initialize the parser registry."""
        self._parsers: Dict[str, Parser] = {}
        self._extension_map: Dict[str, str] = {}
        self._initialized = False
    
    def register(self, parser_id: str, parser: Parser) -> None:
        """
        Register a new parser.
        
        Args:
            parser_id: Unique identifier for the parser
            parser: The parser instance to register
            
        Implementation Notes:
        - Should validate parser interface compliance
        - Should handle duplicate registration gracefully
        - Should update extension mappings
        """
        if parser_id in self._parsers:
            logger.warning(f"Parser {parser_id} already registered, overwriting")
        
        self._parsers[parser_id] = parser
        
        # Update extension mappings
        for extension in parser.supported_extensions:
            if extension in self._extension_map:
                logger.warning(f"Extension {extension} already mapped to {self._extension_map[extension]}")
            self._extension_map[extension] = parser_id
        
        logger.debug(f"Registered parser: {parser_id}")
    
    def get_parser_for_file(self, file_path: Path) -> Optional[Parser]:
        """
        Get the appropriate parser for a file.
        
        Args:
            file_path: Path to the file to parse
            
        Returns:
            Parser instance that can handle the file, or None
            
        Implementation Notes:
        - Should check file extension first
        - Should fall back to content-based detection if needed
        - Should handle multiple extensions (e.g., .spec.ts)
        - Should prefer more specific parsers over generic ones
        """
        if not self._initialized:
            self._load_default_parsers()
        
        # Check by file extension
        extension = file_path.suffix.lower()
        if extension in self._extension_map:
            parser_id = self._extension_map[extension]
            return self._parsers.get(parser_id)
        
        # Check compound extensions (e.g., .spec.js, .test.py)
        if len(file_path.suffixes) > 1:
            compound_ext = ''.join(file_path.suffixes[-2:]).lower()
            if compound_ext in self._extension_map:
                parser_id = self._extension_map[compound_ext]
                return self._parsers.get(parser_id)
        
        # Try each parser's can_parse method
        for parser in self._parsers.values():
            if parser.can_parse(file_path):
                return parser
        
        return None
    
    def list_parsers(self) -> List[Parser]:
        """
        Get all registered parsers.
        
        Returns:
            List of all registered parser instances
        """
        if not self._initialized:
            self._load_default_parsers()
        
        return list(self._parsers.values())
    
    def get_supported_extensions(self) -> Set[str]:
        """
        Get all file extensions supported by registered parsers.
        
        Returns:
            Set of supported file extensions
        """
        return set(self._extension_map.keys())
    
    def _load_default_parsers(self) -> None:
        """
        Load default parsers that come with the scanner.
        
        Implementation Notes:
        - Should discover parsers from the parsers package
        - Should handle import errors gracefully
        - Should log successful/failed parser loads
        - Should support plugin discovery from external packages
        """
        # TODO: Implement parser discovery and loading
        # - Import all parser modules from src.parsers
        # - Instantiate parser classes
        # - Register each parser
        # - Handle configuration loading
        
        logger.info("Loading default parsers...")
        
        # Placeholder for actual parser loading
        # This would typically involve dynamic imports:
        # from ..parsers import python_parser, javascript_parser, etc.
        # self.register("python", python_parser.PythonParser())
        # self.register("javascript", javascript_parser.JavaScriptParser())
        
        self._initialized = True
        logger.info(f"Loaded {len(self._parsers)} parsers")


class PluginRegistry:
    """
    Registry for managing external plugins.
    
    This registry handles discovery and loading of external analyzer and parser plugins,
    supporting the extensible architecture described in the implementation guide.
    """
    
    def __init__(self, analyzer_registry: AnalyzerRegistry, parser_registry: ParserRegistry):
        """
        Initialize the plugin registry.
        
        Args:
            analyzer_registry: Registry to register discovered analyzers
            parser_registry: Registry to register discovered parsers
        """
        self.analyzer_registry = analyzer_registry
        self.parser_registry = parser_registry
        self._plugin_paths: List[Path] = []
    
    def add_plugin_path(self, path: Path) -> None:
        """
        Add a directory to search for plugins.
        
        Args:
            path: Directory path containing plugin modules
            
        Implementation Notes:
        - Should validate path exists and is readable
        - Should handle duplicate paths gracefully
        - Should support both file and directory paths
        """
        if path.exists() and path not in self._plugin_paths:
            self._plugin_paths.append(path)
            logger.debug(f"Added plugin path: {path}")
        else:
            logger.warning(f"Plugin path does not exist or already added: {path}")
    
    def discover_plugins(self) -> None:
        """
        Discover and load plugins from configured paths.
        
        Implementation Notes:
        - Should scan plugin paths for valid plugin modules
        - Should handle plugin loading errors gracefully
        - Should validate plugin interface compliance
        - Should support plugin metadata and versioning
        """
        # TODO: Implement plugin discovery
        # - Scan plugin paths for Python modules
        # - Import and validate plugin modules
        # - Register discovered analyzers and parsers
        # - Handle plugin dependencies and conflicts
        
        logger.info("Discovering plugins...")
        plugins_found = 0
        
        for plugin_path in self._plugin_paths:
            try:
                # Scan for plugin files
                # Load and validate plugins
                # Register with appropriate registries
                pass
            except Exception as e:
                logger.error(f"Error discovering plugins in {plugin_path}: {e}")
        
        logger.info(f"Discovered {plugins_found} plugins")