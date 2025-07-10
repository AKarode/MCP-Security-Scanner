"""
Command Injection Analyzer

This analyzer detects potential command injection vulnerabilities in MCP server code.
It identifies patterns where user-controlled input might be passed to system commands
without proper sanitization.

Detection Patterns:
- Subprocess calls with user input
- Shell command construction with string concatenation
- Dynamic command building from templates
- Unsafe eval() calls that execute system commands
- Process spawning with untrusted parameters

Implementation Notes:
- Should perform data flow analysis to track tainted input
- Should identify sanitization functions and their effectiveness
- Should handle different programming languages' subprocess APIs
- Should consider context-specific risks (e.g., shell vs direct exec)
"""

from typing import List, Dict, Any
from pathlib import Path
import re
import ast
import logging

from ..core.types import (
    Analyzer, ParsedFile, Vulnerability, VulnerabilityType, 
    Severity, Location
)

logger = logging.getLogger(__name__)


class CommandInjectionAnalyzer(Analyzer):
    """
    Analyzer for detecting command injection vulnerabilities.
    
    This analyzer examines code for patterns that could lead to command injection attacks,
    particularly focusing on subprocess calls, shell commands, and dynamic command construction.
    """
    
    def __init__(self):
        """Initialize the command injection analyzer."""
        self.config = {}
        self._dangerous_functions = {}
        self._sanitization_functions = {}
        self._setup_detection_patterns()
    
    @property
    def id(self) -> str:
        """Unique identifier for this analyzer."""
        return "command_injection"
    
    @property
    def description(self) -> str:
        """Human-readable description of what this analyzer detects."""
        return "Detects command injection vulnerabilities in subprocess calls and shell commands"
    
    @property
    def supported_languages(self) -> List[str]:
        """List of programming languages this analyzer supports."""
        return ["python", "javascript", "typescript", "bash", "sh"]
    
    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure the analyzer with custom settings.
        
        Args:
            config: Configuration dictionary with analyzer-specific settings
                   Expected keys:
                   - dangerous_functions: Additional functions to consider dangerous
                   - sanitization_functions: Functions that sanitize input
                   - confidence_threshold: Minimum confidence for reporting (0.0-1.0)
                   - severity_override: Override default severity levels
        """
        self.config = config
        
        # Update dangerous functions if provided
        if "dangerous_functions" in config:
            for language, functions in config["dangerous_functions"].items():
                if language in self._dangerous_functions:
                    self._dangerous_functions[language].update(functions)
        
        # Update sanitization functions if provided
        if "sanitization_functions" in config:
            for language, functions in config["sanitization_functions"].items():
                if language in self._sanitization_functions:
                    self._sanitization_functions[language].update(functions)
        
        logger.debug(f"Configured {self.id} analyzer with {len(config)} settings")
    
    def analyze(self, file: ParsedFile) -> List[Vulnerability]:
        """
        Analyze a parsed file for command injection vulnerabilities.
        
        Args:
            file: The parsed file to analyze
            
        Returns:
            List of vulnerabilities found in the file
            
        Implementation Strategy:
        1. Parse the AST to find function calls that execute commands
        2. Analyze arguments to these calls for user-controlled input
        3. Check for proper sanitization of inputs
        4. Assess the risk level based on context and input sources
        5. Generate vulnerability reports with remediation advice
        """
        vulnerabilities = []
        
        try:
            if file.language == "python":
                vulnerabilities.extend(self._analyze_python(file))
            elif file.language in ["javascript", "typescript"]:
                vulnerabilities.extend(self._analyze_javascript(file))
            elif file.language in ["bash", "sh"]:
                vulnerabilities.extend(self._analyze_shell(file))
            else:
                logger.debug(f"Language {file.language} not supported by {self.id}")
                
        except Exception as e:
            logger.error(f"Error analyzing {file.path} for command injection: {e}")
        
        return vulnerabilities
    
    def _analyze_python(self, file: ParsedFile) -> List[Vulnerability]:
        """
        Analyze Python code for command injection vulnerabilities.
        
        Args:
            file: Parsed Python file
            
        Returns:
            List of vulnerabilities found
            
        Implementation Notes:
        - Should check subprocess module calls (run, call, Popen, etc.)
        - Should analyze os.system() calls
        - Should examine eval() and exec() with command strings
        - Should track variable flow to identify tainted inputs
        - Should recognize common sanitization patterns
        """
        vulnerabilities = []
        
        if not isinstance(file.ast, ast.AST):
            logger.warning(f"Expected AST for Python file {file.path}, got {type(file.ast)}")
            return vulnerabilities
        
        # TODO: Implement Python AST analysis
        # - Walk the AST to find dangerous function calls
        # - Check arguments for user input (request params, CLI args, etc.)
        # - Analyze string concatenation and formatting
        # - Detect shell=True usage in subprocess calls
        # - Check for proper input validation
        
        dangerous_calls = [
            'subprocess.run', 'subprocess.call', 'subprocess.Popen',
            'os.system', 'os.popen', 'os.execv', 'os.execve',
            'eval', 'exec'
        ]
        
        for node in ast.walk(file.ast):
            if isinstance(node, ast.Call):
                # Check if this is a dangerous function call
                call_name = self._get_call_name(node)
                if call_name in dangerous_calls:
                    vulnerability = self._create_vulnerability(
                        file, node, call_name, 
                        "Potential command injection vulnerability"
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_javascript(self, file: ParsedFile) -> List[Vulnerability]:
        """
        Analyze JavaScript/TypeScript code for command injection vulnerabilities.
        
        Args:
            file: Parsed JavaScript/TypeScript file
            
        Returns:
            List of vulnerabilities found
            
        Implementation Notes:
        - Should check child_process module usage (exec, spawn, etc.)
        - Should analyze eval() and Function() constructor calls
        - Should examine template literals with user input
        - Should track variable flow for tainted inputs
        - Should recognize sanitization libraries
        """
        vulnerabilities = []
        
        # TODO: Implement JavaScript/TypeScript analysis
        # - Parse JavaScript AST (using appropriate parser)
        # - Find child_process.exec/spawn calls
        # - Check for eval() usage with user input
        # - Analyze template string construction
        # - Detect shell command construction patterns
        
        # Placeholder implementation with regex patterns
        dangerous_patterns = [
            r'child_process\.exec\(',
            r'child_process\.spawn\(',
            r'eval\(',
            r'Function\(',
            r'require\([\'"]child_process[\'\"]\)'
        ]
        
        for line_num, line in enumerate(file.lines, 1):
            for pattern in dangerous_patterns:
                if re.search(pattern, line):
                    vulnerability = Vulnerability(
                        id=None,
                        type=VulnerabilityType.COMMAND_INJECTION,
                        severity=Severity.HIGH,
                        confidence=0.7,
                        location=Location(file.path, line_num, 1),
                        message=f"Potential command injection via {pattern}",
                        description="Detected potentially dangerous function call that could lead to command injection",
                        remediation="Validate and sanitize all user inputs before passing to system commands"
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_shell(self, file: ParsedFile) -> List[Vulnerability]:
        """
        Analyze shell script code for command injection vulnerabilities.
        
        Args:
            file: Parsed shell script file
            
        Returns:
            List of vulnerabilities found
            
        Implementation Notes:
        - Should check variable expansion without quoting
        - Should analyze eval statements
        - Should examine command substitution patterns
        - Should detect user input sources (read, $1, etc.)
        - Should check for proper quoting and escaping
        """
        vulnerabilities = []
        
        # TODO: Implement shell script analysis
        # - Parse shell script structure
        # - Find variable assignments from user input
        # - Check for unquoted variable expansion
        # - Analyze eval and exec statements
        # - Detect command substitution with user input
        
        # Placeholder implementation with regex patterns
        dangerous_patterns = [
            r'eval\s+\$',
            r'\$\{\w+\}',  # Unquoted variable expansion
            r'`[^`]*\$',   # Command substitution with variables
            r'read\s+\w+.*\$\w+',  # Read input used in commands
        ]
        
        for line_num, line in enumerate(file.lines, 1):
            for pattern in dangerous_patterns:
                if re.search(pattern, line):
                    vulnerability = Vulnerability(
                        id=None,
                        type=VulnerabilityType.COMMAND_INJECTION,
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        location=Location(file.path, line_num, 1),
                        message=f"Potential command injection in shell script: {pattern}",
                        description="Detected shell pattern that could lead to command injection",
                        remediation="Quote all variables and validate user inputs"
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _setup_detection_patterns(self) -> None:
        """Set up language-specific detection patterns."""
        self._dangerous_functions = {
            "python": {
                "subprocess.run", "subprocess.call", "subprocess.Popen",
                "os.system", "os.popen", "os.execv", "os.execve",
                "eval", "exec"
            },
            "javascript": {
                "child_process.exec", "child_process.spawn", "child_process.execFile",
                "eval", "Function"
            },
            "typescript": {
                "child_process.exec", "child_process.spawn", "child_process.execFile",
                "eval", "Function"
            },
            "bash": {
                "eval", "exec", "system"
            },
            "sh": {
                "eval", "exec", "system"
            }
        }
        
        self._sanitization_functions = {
            "python": {
                "shlex.quote", "pipes.quote", "re.escape"
            },
            "javascript": {
                "shelljs.escape", "escape-shell-arg"
            },
            "typescript": {
                "shelljs.escape", "escape-shell-arg"
            }
        }
    
    def _get_call_name(self, node: ast.Call) -> str:
        """
        Extract the function name from an AST call node.
        
        Args:
            node: AST call node
            
        Returns:
            Function name as string
        """
        # TODO: Implement proper call name extraction
        # - Handle attribute access (module.function)
        # - Handle nested calls
        # - Handle aliased imports
        
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        
        return "unknown"
    
    def _create_vulnerability(self, file: ParsedFile, node: ast.AST, 
                            call_name: str, message: str) -> Vulnerability:
        """
        Create a vulnerability object from an AST node.
        
        Args:
            file: The file being analyzed
            node: AST node where vulnerability was found
            call_name: Name of the dangerous function call
            message: Vulnerability description
            
        Returns:
            Vulnerability object
        """
        return Vulnerability(
            id=None,
            type=VulnerabilityType.COMMAND_INJECTION,
            severity=Severity.HIGH,
            confidence=0.8,
            location=Location(file.path, node.lineno, node.col_offset),
            message=message,
            description=f"Potentially dangerous function call: {call_name}",
            remediation="Validate and sanitize all user inputs before passing to system commands. Use parameterized commands when possible."
        )