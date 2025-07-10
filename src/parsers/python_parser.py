"""
Python Parser for MCP Scanner

This parser handles Python source files, extracting AST and metadata
for security analysis.

Implementation Notes:
- Uses Python's built-in ast module for parsing
- Handles syntax errors gracefully
- Extracts file metadata (encoding, size, etc.)
- Supports Python 3.9+ syntax features
"""

import ast
from pathlib import Path
from typing import Optional, List
import logging

from ..core.types import Parser, ParsedFile

logger = logging.getLogger(__name__)


class PythonParser(Parser):
    """
    Parser for Python source files.
    
    This parser uses Python's built-in ast module to parse Python source code
    and extract the Abstract Syntax Tree for security analysis.
    """
    
    def __init__(self):
        """Initialize the Python parser."""
        pass
    
    @property
    def supported_extensions(self) -> List[str]:
        """File extensions this parser can handle."""
        return [".py", ".pyi", ".pyx"]
    
    def can_parse(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the given file.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if this parser can handle the file
            
        Implementation Notes:
        - Should check file extension
        - Should verify file is readable
        - Should optionally check for Python shebang
        """
        # Check file extension
        if file_path.suffix not in self.supported_extensions:
            return False
        
        # Check if file is readable
        if not file_path.is_file() or not file_path.exists():
            return False
        
        # TODO: Add additional checks
        # - Check for Python shebang in files without .py extension
        # - Verify file is not binary
        # - Check file size limits
        
        return True
    
    def parse(self, file_path: Path) -> ParsedFile:
        """
        Parse a Python source file into a ParsedFile object.
        
        Args:
            file_path: Path to the Python file to parse
            
        Returns:
            ParsedFile object containing the parsed content and AST
            
        Raises:
            Exception: If the file cannot be parsed
            
        Implementation Notes:
        - Should detect file encoding automatically
        - Should handle syntax errors gracefully
        - Should extract useful metadata
        - Should preserve original source for reporting
        """
        try:
            # Read file content with proper encoding detection
            content = self._read_file_content(file_path)
            
            # Parse the Python AST
            python_ast = ast.parse(content, filename=str(file_path))
            
            # Create ParsedFile object
            parsed_file = ParsedFile(
                path=file_path,
                content=content,
                language="python",
                ast=python_ast,
                size=len(content),
                encoding="utf-8"  # TODO: Detect actual encoding
            )
            
            logger.debug(f"Successfully parsed Python file: {file_path}")
            return parsed_file
            
        except SyntaxError as e:
            logger.error(f"Syntax error in Python file {file_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to parse Python file {file_path}: {e}")
            raise
    
    def _read_file_content(self, file_path: Path) -> str:
        """
        Read file content with proper encoding detection.
        
        Args:
            file_path: Path to the file to read
            
        Returns:
            File content as string
            
        Implementation Notes:
        - Should detect encoding from BOM or encoding declaration
        - Should handle common encodings (utf-8, latin-1, etc.)
        - Should provide clear error messages for encoding issues
        """
        # TODO: Implement proper encoding detection
        # - Check for BOM (Byte Order Mark)
        # - Look for encoding declaration in first two lines
        # - Fall back to common encodings
        # - Handle encoding errors gracefully
        
        # Simple implementation for now
        encodings_to_try = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
        
        for encoding in encodings_to_try:
            try:
                return file_path.read_text(encoding=encoding)
            except UnicodeDecodeError:
                continue
        
        # If all encodings fail, read as binary and decode with errors
        raw_content = file_path.read_bytes()
        return raw_content.decode('utf-8', errors='replace')
    
    def extract_metadata(self, python_ast: ast.AST) -> dict:
        """
        Extract metadata from Python AST.
        
        Args:
            python_ast: Parsed Python AST
            
        Returns:
            Dictionary containing extracted metadata
            
        Implementation Notes:
        - Should extract imports and dependencies
        - Should identify functions, classes, and variables
        - Should find string literals and constants
        - Should identify potential security-relevant patterns
        """
        metadata = {
            "imports": [],
            "functions": [],
            "classes": [],
            "string_literals": [],
            "constants": []
        }
        
        # TODO: Implement comprehensive metadata extraction
        # - Walk the AST to find all relevant nodes
        # - Extract import statements and modules
        # - Identify function and class definitions
        # - Collect string literals for analysis
        # - Find variable assignments and constants
        
        for node in ast.walk(python_ast):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    metadata["imports"].append(alias.name)
            
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    metadata["imports"].append(node.module)
            
            elif isinstance(node, ast.FunctionDef):
                metadata["functions"].append(node.name)
            
            elif isinstance(node, ast.ClassDef):
                metadata["classes"].append(node.name)
            
            elif isinstance(node, ast.Str):
                metadata["string_literals"].append(node.s)
            
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                metadata["string_literals"].append(node.value)
        
        return metadata