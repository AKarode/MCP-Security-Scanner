"""
MCP Permissions Analyzer

This analyzer specifically focuses on Model Context Protocol (MCP) server configurations
and identifies over-privileged permissions that could be exploited by malicious actors.

Detection Areas:
- MCP server permission configurations
- Tool access controls
- Resource access permissions
- Protocol-level security settings
- Permission escalation opportunities

Implementation Notes:
- Should parse mcp.json and similar configuration files
- Should understand MCP protocol permission model
- Should identify minimum privilege violations
- Should detect wildcard permissions and overly broad access
"""

from typing import List, Dict, Any, Set
from pathlib import Path
import json
import yaml
import logging

from ..core.types import (
    Analyzer, ParsedFile, Vulnerability, VulnerabilityType, 
    Severity, Location
)

logger = logging.getLogger(__name__)


class McpPermissionAnalyzer(Analyzer):
    """
    Analyzer for MCP-specific permission and configuration issues.
    
    This analyzer examines MCP server configurations to identify security issues
    related to over-privileged permissions and insecure settings.
    """
    
    def __init__(self):
        """Initialize the MCP permission analyzer."""
        self.config = {}
        self._dangerous_permissions = set()
        self._sensitive_resources = set()
        self._setup_permission_rules()
    
    @property
    def id(self) -> str:
        """Unique identifier for this analyzer."""
        return "mcp_permissions"
    
    @property
    def description(self) -> str:
        """Human-readable description of what this analyzer detects."""
        return "Analyzes MCP server configurations for over-privileged permissions and insecure settings"
    
    @property
    def supported_languages(self) -> List[str]:
        """List of file types this analyzer supports."""
        return ["json", "yaml", "toml"]
    
    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure the analyzer with MCP-specific settings.
        
        Args:
            config: Configuration dictionary with analyzer-specific settings
                   Expected keys:
                   - dangerous_permissions: Additional permissions to flag
                   - allowed_resources: Resources that are acceptable to access
                   - min_privilege_mode: Enforce minimum privilege checking
                   - org_specific_rules: Organization-specific permission rules
        """
        self.config = config
        
        # Update dangerous permissions if provided
        if "dangerous_permissions" in config:
            self._dangerous_permissions.update(config["dangerous_permissions"])
        
        # Update sensitive resources if provided
        if "sensitive_resources" in config:
            self._sensitive_resources.update(config["sensitive_resources"])
        
        logger.debug(f"Configured {self.id} analyzer with {len(config)} settings")
    
    def analyze(self, file: ParsedFile) -> List[Vulnerability]:
        """
        Analyze MCP configuration files for permission issues.
        
        Args:
            file: The parsed configuration file to analyze
            
        Returns:
            List of vulnerabilities found in the configuration
            
        Implementation Strategy:
        1. Parse MCP configuration files (mcp.json, mcp.yaml, etc.)
        2. Examine permission grants and access controls
        3. Identify over-privileged configurations
        4. Check for insecure default settings
        5. Validate resource access patterns
        """
        vulnerabilities = []
        
        try:
            # Check if this is an MCP configuration file
            if not self._is_mcp_config_file(file.path):
                return vulnerabilities
            
            # Parse the configuration
            config_data = self._parse_config_file(file)
            if not config_data:
                return vulnerabilities
            
            # Analyze different aspects of the configuration
            vulnerabilities.extend(self._analyze_permissions(file, config_data))
            vulnerabilities.extend(self._analyze_tools(file, config_data))
            vulnerabilities.extend(self._analyze_resources(file, config_data))
            vulnerabilities.extend(self._analyze_security_settings(file, config_data))
            
        except Exception as e:
            logger.error(f"Error analyzing MCP configuration {file.path}: {e}")
        
        return vulnerabilities
    
    def _is_mcp_config_file(self, file_path: Path) -> bool:
        """
        Check if a file is an MCP configuration file.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if this appears to be an MCP configuration file
        """
        # Check filename patterns
        mcp_filenames = [
            "mcp.json", "mcp.yaml", "mcp.yml", "mcp.toml",
            ".mcp.json", ".mcp.yaml", ".mcp.yml",
            "mcp-config.json", "mcp-config.yaml"
        ]
        
        if file_path.name.lower() in mcp_filenames:
            return True
        
        # Check for MCP-specific content indicators
        # TODO: Implement content-based detection
        # - Look for MCP-specific keys in the file
        # - Check for protocol version indicators
        # - Examine tool and resource definitions
        
        return False
    
    def _parse_config_file(self, file: ParsedFile) -> Dict[str, Any]:
        """
        Parse an MCP configuration file.
        
        Args:
            file: The configuration file to parse
            
        Returns:
            Parsed configuration as dictionary, or None if parsing fails
        """
        try:
            if file.path.suffix.lower() == ".json":
                return json.loads(file.content)
            elif file.path.suffix.lower() in [".yaml", ".yml"]:
                return yaml.safe_load(file.content)
            elif file.path.suffix.lower() == ".toml":
                # TODO: Add TOML parsing support
                logger.warning(f"TOML parsing not yet implemented for {file.path}")
                return None
        except Exception as e:
            logger.error(f"Failed to parse MCP config {file.path}: {e}")
            return None
    
    def _analyze_permissions(self, file: ParsedFile, config: Dict[str, Any]) -> List[Vulnerability]:
        """
        Analyze permission configurations in MCP settings.
        
        Args:
            file: The configuration file
            config: Parsed configuration data
            
        Returns:
            List of permission-related vulnerabilities
            
        Implementation Notes:
        - Should check for wildcard permissions
        - Should identify overly broad access grants
        - Should validate permission necessity
        - Should check for permission escalation paths
        """
        vulnerabilities = []
        
        # TODO: Implement comprehensive permission analysis
        # - Parse permission structure from MCP config
        # - Check for wildcard or overly broad permissions
        # - Validate against principle of least privilege
        # - Identify potential permission escalation
        
        # Check for permissions section
        permissions = config.get("permissions", {})
        if not permissions:
            # Missing permissions configuration might be a security issue
            vulnerability = Vulnerability(
                id=None,
                type=VulnerabilityType.MCP_OVERPRIVILEGED,
                severity=Severity.MEDIUM,
                confidence=0.7,
                location=Location(file.path, 1, 1),
                message="Missing explicit permissions configuration",
                description="MCP server lacks explicit permission configuration, which may default to overly permissive settings",
                remediation="Define explicit permissions following the principle of least privilege"
            )
            vulnerabilities.append(vulnerability)
        
        # Check for dangerous permission patterns
        for permission_key, permission_value in permissions.items():
            if self._is_dangerous_permission(permission_key, permission_value):
                vulnerability = Vulnerability(
                    id=None,
                    type=VulnerabilityType.MCP_OVERPRIVILEGED,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    location=Location(file.path, 1, 1),  # TODO: Get actual line number
                    message=f"Potentially dangerous permission: {permission_key}",
                    description=f"Permission '{permission_key}' may grant excessive access",
                    remediation="Review and restrict permission scope to minimum necessary access"
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_tools(self, file: ParsedFile, config: Dict[str, Any]) -> List[Vulnerability]:
        """
        Analyze tool configurations for security issues.
        
        Args:
            file: The configuration file
            config: Parsed configuration data
            
        Returns:
            List of tool-related vulnerabilities
            
        Implementation Notes:
        - Should check tool access permissions
        - Should validate tool parameter restrictions
        - Should identify potentially dangerous tools
        - Should check for proper tool sandboxing
        """
        vulnerabilities = []
        
        # TODO: Implement tool security analysis
        # - Parse tool definitions and permissions
        # - Check for dangerous tool capabilities
        # - Validate parameter restrictions
        # - Identify tools with shell/file system access
        
        tools = config.get("tools", [])
        for tool_index, tool in enumerate(tools):
            if isinstance(tool, dict):
                # Check for dangerous tool capabilities
                if self._is_dangerous_tool(tool):
                    vulnerability = Vulnerability(
                        id=None,
                        type=VulnerabilityType.MCP_DANGEROUS_TOOL,
                        severity=Severity.HIGH,
                        confidence=0.8,
                        location=Location(file.path, 1, 1),  # TODO: Get actual line number
                        message=f"Potentially dangerous tool configuration: {tool.get('name', 'unnamed')}",
                        description="Tool configuration may allow dangerous operations",
                        remediation="Review tool permissions and restrict capabilities to minimum necessary"
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_resources(self, file: ParsedFile, config: Dict[str, Any]) -> List[Vulnerability]:
        """
        Analyze resource access configurations.
        
        Args:
            file: The configuration file
            config: Parsed configuration data
            
        Returns:
            List of resource-related vulnerabilities
            
        Implementation Notes:
        - Should check resource access patterns
        - Should validate resource permission scopes
        - Should identify access to sensitive resources
        - Should check for proper resource isolation
        """
        vulnerabilities = []
        
        # TODO: Implement resource access analysis
        # - Parse resource definitions and access controls
        # - Check for overly broad resource access
        # - Identify access to sensitive system resources
        # - Validate resource isolation and sandboxing
        
        resources = config.get("resources", [])
        for resource_index, resource in enumerate(resources):
            if isinstance(resource, dict):
                # Check for sensitive resource access
                if self._accesses_sensitive_resource(resource):
                    vulnerability = Vulnerability(
                        id=None,
                        type=VulnerabilityType.MCP_OVERPRIVILEGED,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        location=Location(file.path, 1, 1),  # TODO: Get actual line number
                        message=f"Access to sensitive resource: {resource.get('name', 'unnamed')}",
                        description="Configuration grants access to potentially sensitive resources",
                        remediation="Restrict resource access to minimum necessary scope"
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_security_settings(self, file: ParsedFile, config: Dict[str, Any]) -> List[Vulnerability]:
        """
        Analyze general security settings in MCP configuration.
        
        Args:
            file: The configuration file
            config: Parsed configuration data
            
        Returns:
            List of security setting vulnerabilities
            
        Implementation Notes:
        - Should check for insecure default settings
        - Should validate authentication configurations
        - Should check for proper error handling settings
        - Should identify missing security controls
        """
        vulnerabilities = []
        
        # TODO: Implement security settings analysis
        # - Check authentication and authorization settings
        # - Validate encryption and transport security
        # - Check for proper error handling configuration
        # - Identify missing security controls
        
        # Check for missing authentication
        if "auth" not in config and "authentication" not in config:
            vulnerability = Vulnerability(
                id=None,
                type=VulnerabilityType.MCP_OVERPRIVILEGED,
                severity=Severity.MEDIUM,
                confidence=0.6,
                location=Location(file.path, 1, 1),
                message="Missing authentication configuration",
                description="MCP server configuration lacks authentication settings",
                remediation="Configure appropriate authentication mechanisms"
            )
            vulnerabilities.append(vulnerability)
        
        # Check for debug mode in production
        if config.get("debug", False) or config.get("development", False):
            vulnerability = Vulnerability(
                id=None,
                type=VulnerabilityType.MCP_OVERPRIVILEGED,
                severity=Severity.MEDIUM,
                confidence=0.8,
                location=Location(file.path, 1, 1),
                message="Debug mode enabled",
                description="Debug or development mode appears to be enabled",
                remediation="Disable debug mode in production environments"
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _setup_permission_rules(self) -> None:
        """Set up rules for identifying dangerous permissions and resources."""
        self._dangerous_permissions = {
            "*",  # Wildcard permission
            "admin",
            "root",
            "shell",
            "exec",
            "file:write",
            "file:delete",
            "network:*",
            "system:*"
        }
        
        self._sensitive_resources = {
            "/etc/",
            "/root/",
            "/home/",
            "~/.ssh/",
            "~/.aws/",
            "~/.config/",
            "file:///",
            "system:root",
            "network:external"
        }
    
    def _is_dangerous_permission(self, permission_key: str, permission_value: Any) -> bool:
        """
        Check if a permission is potentially dangerous.
        
        Args:
            permission_key: The permission identifier
            permission_value: The permission configuration
            
        Returns:
            True if the permission is potentially dangerous
        """
        # Check against known dangerous permissions
        if permission_key in self._dangerous_permissions:
            return True
        
        # Check for wildcard patterns
        if "*" in permission_key:
            return True
        
        # Check permission value for dangerous patterns
        if isinstance(permission_value, dict):
            if permission_value.get("scope") == "*":
                return True
            if permission_value.get("access") == "full":
                return True
        
        return False
    
    def _is_dangerous_tool(self, tool_config: Dict[str, Any]) -> bool:
        """
        Check if a tool configuration is potentially dangerous.
        
        Args:
            tool_config: Tool configuration dictionary
            
        Returns:
            True if the tool is potentially dangerous
        """
        dangerous_capabilities = [
            "shell", "exec", "command", "process",
            "file_write", "file_delete", "network",
            "system", "admin"
        ]
        
        # Check tool capabilities
        capabilities = tool_config.get("capabilities", [])
        for capability in capabilities:
            if capability in dangerous_capabilities:
                return True
        
        # Check tool type
        tool_type = tool_config.get("type", "")
        if tool_type in dangerous_capabilities:
            return True
        
        return False
    
    def _accesses_sensitive_resource(self, resource_config: Dict[str, Any]) -> bool:
        """
        Check if a resource configuration accesses sensitive resources.
        
        Args:
            resource_config: Resource configuration dictionary
            
        Returns:
            True if the resource accesses sensitive areas
        """
        # Check resource path or URI
        resource_path = resource_config.get("path", "")
        resource_uri = resource_config.get("uri", "")
        
        for sensitive_resource in self._sensitive_resources:
            if sensitive_resource in resource_path or sensitive_resource in resource_uri:
                return True
        
        return False