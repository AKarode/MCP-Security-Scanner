"""
Secrets Detection Analyzer

This analyzer identifies exposed secrets, credentials, and sensitive information in MCP server code.
It uses multiple detection techniques including entropy analysis, regex patterns, and contextual analysis.

Detection Patterns:
- API keys and tokens (GitHub, AWS, etc.)
- Database connection strings
- Private keys and certificates
- Hardcoded passwords
- JWT tokens and session keys
- High-entropy strings that might be secrets

Implementation Notes:
- Should use entropy analysis to detect random-looking strings
- Should maintain a database of known secret patterns
- Should avoid false positives from test data and examples
- Should support custom secret patterns for organization-specific secrets
"""

from typing import List, Dict, Any, Set, Tuple
from pathlib import Path
import re
import math
import base64
import logging

from ..core.types import (
    Analyzer, ParsedFile, Vulnerability, VulnerabilityType, 
    Severity, Location
)

logger = logging.getLogger(__name__)


class SecretsAnalyzer(Analyzer):
    """
    Analyzer for detecting exposed secrets and credentials.
    
    This analyzer uses multiple techniques to identify potentially sensitive information
    that should not be hardcoded in source code.
    """
    
    def __init__(self):
        """Initialize the secrets analyzer."""
        self.config = {}
        self._secret_patterns = {}
        self._false_positive_patterns = {}
        self._entropy_threshold = 4.5
        self._min_secret_length = 8
        self._max_secret_length = 256
        self._setup_detection_patterns()
    
    @property
    def id(self) -> str:
        """Unique identifier for this analyzer."""
        return "secrets_detection"
    
    @property
    def description(self) -> str:
        """Human-readable description of what this analyzer detects."""
        return "Detects exposed secrets, API keys, and sensitive credentials in source code"
    
    @property
    def supported_languages(self) -> List[str]:
        """List of programming languages this analyzer supports."""
        return ["python", "javascript", "typescript", "json", "yaml", "toml", "env", "bash", "sh"]
    
    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure the analyzer with custom settings.
        
        Args:
            config: Configuration dictionary with analyzer-specific settings
                   Expected keys:
                   - entropy_threshold: Minimum entropy for high-entropy detection
                   - min_secret_length: Minimum length for secret candidates
                   - max_secret_length: Maximum length for secret candidates
                   - custom_patterns: Additional regex patterns for secrets
                   - whitelist_patterns: Patterns to ignore (false positives)
                   - confidence_threshold: Minimum confidence for reporting
        """
        self.config = config
        
        # Update thresholds if provided
        self._entropy_threshold = config.get("entropy_threshold", self._entropy_threshold)
        self._min_secret_length = config.get("min_secret_length", self._min_secret_length)
        self._max_secret_length = config.get("max_secret_length", self._max_secret_length)
        
        # Add custom patterns if provided
        if "custom_patterns" in config:
            for name, pattern in config["custom_patterns"].items():
                self._secret_patterns[name] = pattern
        
        # Add whitelist patterns if provided
        if "whitelist_patterns" in config:
            for name, pattern in config["whitelist_patterns"].items():
                self._false_positive_patterns[name] = pattern
        
        logger.debug(f"Configured {self.id} analyzer with {len(config)} settings")
    
    def analyze(self, file: ParsedFile) -> List[Vulnerability]:
        """
        Analyze a parsed file for exposed secrets and credentials.
        
        Args:
            file: The parsed file to analyze
            
        Returns:
            List of vulnerabilities found in the file
            
        Implementation Strategy:
        1. Apply regex patterns to find known secret formats
        2. Perform entropy analysis on string literals
        3. Check for contextual clues (variable names, comments)
        4. Filter out false positives and test data
        5. Assess confidence based on multiple factors
        """
        vulnerabilities = []
        
        try:
            # Pattern-based detection
            vulnerabilities.extend(self._pattern_based_detection(file))
            
            # Entropy-based detection
            vulnerabilities.extend(self._entropy_based_detection(file))
            
            # Context-based detection
            vulnerabilities.extend(self._context_based_detection(file))
            
            # Remove duplicates and false positives
            vulnerabilities = self._filter_vulnerabilities(vulnerabilities, file)
            
        except Exception as e:
            logger.error(f"Error analyzing {file.path} for secrets: {e}")
        
        return vulnerabilities
    
    def _pattern_based_detection(self, file: ParsedFile) -> List[Vulnerability]:
        """
        Detect secrets using predefined regex patterns.
        
        Args:
            file: The file to analyze
            
        Returns:
            List of vulnerabilities found using pattern matching
            
        Implementation Notes:
        - Should check each line against known secret patterns
        - Should extract the matched secret value
        - Should determine confidence based on pattern specificity
        - Should handle multi-line secrets (certificates, keys)
        """
        vulnerabilities = []
        
        # TODO: Implement comprehensive pattern matching
        # - Apply each regex pattern to file content
        # - Extract matched groups for secret values
        # - Determine severity based on secret type
        # - Handle line-by-line and multi-line matching
        
        for line_num, line in enumerate(file.lines, 1):
            for pattern_name, pattern_info in self._secret_patterns.items():
                regex = pattern_info["regex"]
                severity = pattern_info["severity"]
                confidence = pattern_info["confidence"]
                
                matches = re.finditer(regex, line, re.IGNORECASE)
                for match in matches:
                    # Check if this is a false positive
                    if self._is_false_positive(match.group(), line):
                        continue
                    
                    vulnerability = Vulnerability(
                        id=None,
                        type=VulnerabilityType.SECRETS_EXPOSURE,
                        severity=severity,
                        confidence=confidence,
                        location=Location(file.path, line_num, match.start()),
                        message=f"Potential {pattern_name} detected",
                        description=f"Found what appears to be a {pattern_name} in source code",
                        remediation=f"Remove {pattern_name} from source code and use environment variables or secure configuration",
                        metadata={"pattern": pattern_name, "match": match.group()}
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _entropy_based_detection(self, file: ParsedFile) -> List[Vulnerability]:
        """
        Detect secrets using entropy analysis of string literals.
        
        Args:
            file: The file to analyze
            
        Returns:
            List of vulnerabilities found using entropy analysis
            
        Implementation Notes:
        - Should extract string literals from code
        - Should calculate Shannon entropy for each string
        - Should filter by length and character set
        - Should use contextual clues to improve confidence
        """
        vulnerabilities = []
        
        # TODO: Implement entropy-based detection
        # - Parse string literals from AST or regex
        # - Calculate Shannon entropy for each string
        # - Filter by entropy threshold and length
        # - Check for base64/hex encoding patterns
        # - Use variable names as context clues
        
        # Regex patterns for common string formats
        string_patterns = [
            r'"([^"]{' + str(self._min_secret_length) + r',' + str(self._max_secret_length) + r'})"',
            r"'([^']{" + str(self._min_secret_length) + r',' + str(self._max_secret_length) + r"})'",
            r'`([^`]{' + str(self._min_secret_length) + r',' + str(self._max_secret_length) + r'})`'
        ]
        
        for line_num, line in enumerate(file.lines, 1):
            for pattern in string_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    string_value = match.group(1)
                    entropy = self._calculate_entropy(string_value)
                    
                    if entropy >= self._entropy_threshold:
                        # Check if this looks like a secret
                        if self._looks_like_secret(string_value, line):
                            vulnerability = Vulnerability(
                                id=None,
                                type=VulnerabilityType.SECRETS_EXPOSURE,
                                severity=Severity.MEDIUM,
                                confidence=min(0.9, entropy / 6.0),  # Scale entropy to confidence
                                location=Location(file.path, line_num, match.start()),
                                message="High-entropy string detected",
                                description=f"Found high-entropy string (entropy: {entropy:.2f}) that may be a secret",
                                remediation="If this is a secret, move it to environment variables or secure configuration",
                                metadata={"entropy": entropy, "value_length": len(string_value)}
                            )
                            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _context_based_detection(self, file: ParsedFile) -> List[Vulnerability]:
        """
        Detect secrets using contextual clues like variable names and comments.
        
        Args:
            file: The file to analyze
            
        Returns:
            List of vulnerabilities found using context analysis
            
        Implementation Notes:
        - Should analyze variable names for secret-related keywords
        - Should check comments for leaked credentials
        - Should look for configuration patterns
        - Should consider file types and locations
        """
        vulnerabilities = []
        
        # TODO: Implement context-based detection
        # - Parse variable assignments and their values
        # - Check variable names against suspicious keywords
        # - Analyze comments for credentials
        # - Look for configuration file patterns
        
        # Keywords that might indicate secrets
        secret_keywords = [
            "password", "passwd", "pwd", "pass",
            "secret", "key", "token", "auth",
            "api_key", "apikey", "access_key",
            "private_key", "private", "credential",
            "jwt", "bearer", "oauth"
        ]
        
        for line_num, line in enumerate(file.lines, 1):
            line_lower = line.lower()
            
            # Check for suspicious variable names with values
            for keyword in secret_keywords:
                if keyword in line_lower:
                    # Look for assignment patterns
                    assignment_patterns = [
                        rf'{keyword}\s*[:=]\s*["\']([^"\']+)["\']',
                        rf'{keyword}\s*[:=]\s*(\w+)',
                        rf'["\']({keyword})["\']:\s*["\']([^"\']+)["\']'
                    ]
                    
                    for pattern in assignment_patterns:
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            if self._is_false_positive(match.group(), line):
                                continue
                            
                            vulnerability = Vulnerability(
                                id=None,
                                type=VulnerabilityType.SECRETS_EXPOSURE,
                                severity=Severity.MEDIUM,
                                confidence=0.7,
                                location=Location(file.path, line_num, match.start()),
                                message=f"Potential secret in variable containing '{keyword}'",
                                description=f"Found suspicious variable assignment that may contain a secret",
                                remediation="Use environment variables or secure configuration for secrets",
                                metadata={"keyword": keyword, "context": "variable_assignment"}
                            )
                            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _filter_vulnerabilities(self, vulnerabilities: List[Vulnerability], 
                              file: ParsedFile) -> List[Vulnerability]:
        """
        Filter vulnerabilities to remove false positives and duplicates.
        
        Args:
            vulnerabilities: List of candidate vulnerabilities
            file: The file being analyzed
            
        Returns:
            Filtered list of vulnerabilities
            
        Implementation Notes:
        - Should remove duplicates at the same location
        - Should filter out test files and example data
        - Should apply whitelist patterns
        - Should consider file paths and naming conventions
        """
        filtered = []
        seen_locations = set()
        
        for vuln in vulnerabilities:
            # Remove duplicates at same location
            location_key = (vuln.location.file, vuln.location.line, vuln.location.column)
            if location_key in seen_locations:
                continue
            seen_locations.add(location_key)
            
            # Check if this is in a test file
            if self._is_test_file(file.path):
                vuln.confidence *= 0.5  # Reduce confidence for test files
                vuln.severity = Severity.LOW
            
            # Check if this is an example or documentation
            if self._is_example_file(file.path):
                vuln.confidence *= 0.3  # Significantly reduce confidence
                vuln.severity = Severity.INFO
            
            # Apply confidence threshold
            confidence_threshold = self.config.get("confidence_threshold", 0.5)
            if vuln.confidence >= confidence_threshold:
                filtered.append(vuln)
        
        return filtered
    
    def _setup_detection_patterns(self) -> None:
        """Set up regex patterns for detecting various types of secrets."""
        self._secret_patterns = {
            "aws_access_key": {
                "regex": r"AKIA[0-9A-Z]{16}",
                "severity": Severity.HIGH,
                "confidence": 0.9
            },
            "aws_secret_key": {
                "regex": r"[0-9a-zA-Z/+]{40}",
                "severity": Severity.HIGH,
                "confidence": 0.7
            },
            "github_token": {
                "regex": r"ghp_[0-9a-zA-Z]{36}",
                "severity": Severity.HIGH,
                "confidence": 0.95
            },
            "jwt_token": {
                "regex": r"eyJ[0-9a-zA-Z_-]*\.[0-9a-zA-Z_-]*\.[0-9a-zA-Z_-]*",
                "severity": Severity.MEDIUM,
                "confidence": 0.8
            },
            "private_key": {
                "regex": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
                "severity": Severity.CRITICAL,
                "confidence": 0.95
            },
            "database_url": {
                "regex": r"(postgresql|mysql|mongodb)://[^\\s]+",
                "severity": Severity.HIGH,
                "confidence": 0.8
            },
            "generic_secret": {
                "regex": r"['\"]?[a-zA-Z0-9_-]*(?:secret|key|token|password)['\"]?\s*[:=]\s*['\"]([^'\"\\s]+)['\"]",
                "severity": Severity.MEDIUM,
                "confidence": 0.6
            }
        }
        
        # Patterns that commonly result in false positives
        self._false_positive_patterns = {
            "placeholder": re.compile(r"(your|my|test|example|dummy|placeholder|xxx|yyy|zzz)", re.IGNORECASE),
            "template": re.compile(r"(\{\{|\$\{|%s|%d|<[^>]+>)"),
            "short_common": re.compile(r"^(test|admin|user|password|secret|key|token|auth)$", re.IGNORECASE),
            "all_same": re.compile(r"^(.)\1+$"),  # All same character
            "sequential": re.compile(r"(123|abc|qwerty|password)", re.IGNORECASE)
        }
    
    def _calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string.
        
        Args:
            string: The string to analyze
            
        Returns:
            Shannon entropy value
        """
        if not string:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        length = len(string)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _looks_like_secret(self, string: str, context: str) -> bool:
        """
        Determine if a high-entropy string looks like a secret.
        
        Args:
            string: The string to evaluate
            context: The line context where the string appears
            
        Returns:
            True if the string appears to be a secret
        """
        # Check for base64 patterns
        try:
            base64.b64decode(string, validate=True)
            return True  # Valid base64 is often used for secrets
        except Exception:
            pass
        
        # Check for hex patterns
        if re.match(r'^[0-9a-fA-F]+$', string) and len(string) >= 16:
            return True
        
        # Check context for secret-related keywords
        secret_context = any(keyword in context.lower() for keyword in [
            "secret", "key", "token", "password", "auth", "credential"
        ])
        
        return secret_context
    
    def _is_false_positive(self, value: str, context: str) -> bool:
        """
        Check if a detected secret is likely a false positive.
        
        Args:
            value: The detected secret value
            context: The line context
            
        Returns:
            True if this is likely a false positive
        """
        for pattern in self._false_positive_patterns.values():
            if pattern.search(value) or pattern.search(context):
                return True
        
        return False
    
    def _is_test_file(self, file_path: Path) -> bool:
        """Check if a file is a test file."""
        test_indicators = ["test", "spec", "mock", "fixture", "__tests__"]
        path_str = str(file_path).lower()
        return any(indicator in path_str for indicator in test_indicators)
    
    def _is_example_file(self, file_path: Path) -> bool:
        """Check if a file is an example or documentation file."""
        example_indicators = ["example", "demo", "sample", "docs", "readme", "tutorial"]
        path_str = str(file_path).lower()
        return any(indicator in path_str for indicator in example_indicators)