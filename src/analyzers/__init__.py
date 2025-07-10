"""
Security analyzers for the MCP Scanner.

This package contains all the security analyzers that detect various types of vulnerabilities
in MCP server code. Each analyzer implements the Analyzer interface and focuses on specific
categories of security issues.

Available Analyzers:
- CommandInjectionAnalyzer: Detects command injection vulnerabilities
- SecretsAnalyzer: Identifies exposed secrets and credentials
- PromptInjectionAnalyzer: Finds prompt injection attack vectors
- McpPermissionAnalyzer: Analyzes MCP permission configurations
- McpToolAnalyzer: Reviews MCP tool implementations for security issues
- SqlInjectionAnalyzer: Detects SQL injection vulnerabilities
- PathTraversalAnalyzer: Identifies path traversal vulnerabilities
- EvalInjectionAnalyzer: Finds unsafe eval() usage
- TemplateInjectionAnalyzer: Detects template injection vulnerabilities
- InsecureRandomnessAnalyzer: Identifies weak random number generation
"""

from .command_injection import CommandInjectionAnalyzer
from .secrets_detection import SecretsAnalyzer
from .prompt_injection import PromptInjectionAnalyzer
from .mcp_permissions import McpPermissionAnalyzer
from .mcp_tools import McpToolAnalyzer
from .sql_injection import SqlInjectionAnalyzer
from .path_traversal import PathTraversalAnalyzer
from .eval_injection import EvalInjectionAnalyzer
from .template_injection import TemplateInjectionAnalyzer
from .insecure_randomness import InsecureRandomnessAnalyzer

__all__ = [
    'CommandInjectionAnalyzer',
    'SecretsAnalyzer', 
    'PromptInjectionAnalyzer',
    'McpPermissionAnalyzer',
    'McpToolAnalyzer',
    'SqlInjectionAnalyzer',
    'PathTraversalAnalyzer',
    'EvalInjectionAnalyzer',
    'TemplateInjectionAnalyzer',
    'InsecureRandomnessAnalyzer'
]