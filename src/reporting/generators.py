"""
Report generators for MCP Scanner

This module provides various report generators that can output scan results
in different formats (JSON, HTML, Markdown, etc.).

Implementation Notes:
- Should support multiple output formats
- Should provide consistent formatting across formats
- Should include all relevant vulnerability information
- Should support customizable report templates
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import logging

from ..core.types import ScanResult, Vulnerability, Severity

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Base class for report generators.
    
    This class provides the interface for generating reports in various formats
    and includes common functionality used by all report generators.
    """
    
    def __init__(self, output_format: str):
        """
        Initialize the report generator.
        
        Args:
            output_format: The output format to generate (json, html, markdown, text)
        """
        self.output_format = output_format.lower()
        self.supported_formats = ["json", "html", "markdown", "text"]
        
        if self.output_format not in self.supported_formats:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def generate(self, scan_result: ScanResult) -> str:
        """
        Generate a report from scan results.
        
        Args:
            scan_result: The scan results to generate a report from
            
        Returns:
            Generated report as string
            
        Implementation Notes:
        - Should delegate to format-specific generators
        - Should handle generation errors gracefully
        - Should include all relevant information
        - Should be consistent across formats
        """
        try:
            if self.output_format == "json":
                return self._generate_json(scan_result)
            elif self.output_format == "html":
                return self._generate_html(scan_result)
            elif self.output_format == "markdown":
                return self._generate_markdown(scan_result)
            elif self.output_format == "text":
                return self._generate_text(scan_result)
            else:
                raise ValueError(f"Unsupported format: {self.output_format}")
                
        except Exception as e:
            logger.error(f"Failed to generate {self.output_format} report: {e}")
            raise
    
    def _generate_json(self, scan_result: ScanResult) -> str:
        """
        Generate a JSON report.
        
        Args:
            scan_result: The scan results to report
            
        Returns:
            JSON-formatted report string
            
        Implementation Notes:
        - Should include all vulnerability details
        - Should preserve data types and structure
        - Should be machine-readable
        - Should include metadata for tools integration
        """
        # Convert scan result to dictionary
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "scanner_version": scan_result.scanner_version,
                "scan_duration": scan_result.scan_duration,
                "files_scanned": scan_result.files_scanned,
                "total_vulnerabilities": scan_result.total_vulnerabilities
            },
            "summary": {
                "vulnerabilities_by_severity": {
                    severity.value: count 
                    for severity, count in scan_result.vulnerabilities_by_severity.items()
                }
            },
            "vulnerabilities": []
        }
        
        # Add vulnerability details
        for vuln in scan_result.vulnerabilities:
            vuln_data = {
                "id": vuln.id,
                "type": vuln.type.value,
                "severity": vuln.severity.value,
                "confidence": vuln.confidence,
                "location": {
                    "file": str(vuln.location.file),
                    "line": vuln.location.line,
                    "column": vuln.location.column
                },
                "message": vuln.message,
                "description": vuln.description,
                "remediation": vuln.remediation,
                "references": vuln.references,
                "metadata": vuln.metadata
            }
            report_data["vulnerabilities"].append(vuln_data)
        
        return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    def _generate_html(self, scan_result: ScanResult) -> str:
        """
        Generate an HTML report.
        
        Args:
            scan_result: The scan results to report
            
        Returns:
            HTML-formatted report string
            
        Implementation Notes:
        - Should create a visually appealing report
        - Should include interactive elements where useful
        - Should be responsive and accessible
        - Should include styling for different severity levels
        """
        # TODO: Implement HTML report generation
        # - Create HTML template with CSS styling
        # - Include interactive features (filtering, sorting)
        # - Add charts and visualizations
        # - Ensure responsive design
        # - Include source code snippets
        
        severity_colors = {
            Severity.CRITICAL: "#dc3545",
            Severity.HIGH: "#fd7e14",
            Severity.MEDIUM: "#ffc107",
            Severity.LOW: "#28a745",
            Severity.INFO: "#17a2b8"
        }
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Scanner Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .summary-card {{ background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .vulnerability {{ background: white; padding: 15px; margin-bottom: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid; }}
        .severity-critical {{ border-left-color: {severity_colors[Severity.CRITICAL]}; }}
        .severity-high {{ border-left-color: {severity_colors[Severity.HIGH]}; }}
        .severity-medium {{ border-left-color: {severity_colors[Severity.MEDIUM]}; }}
        .severity-low {{ border-left-color: {severity_colors[Severity.LOW]}; }}
        .severity-info {{ border-left-color: {severity_colors[Severity.INFO]}; }}
        .location {{ color: #666; font-size: 0.9em; }}
        .remediation {{ background: #f8f9fa; padding: 10px; border-radius: 3px; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>MCP Scanner Security Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Files Scanned: {scan_result.files_scanned}</p>
        <p>Scan Duration: {scan_result.scan_duration:.2f} seconds</p>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <h3>Total Vulnerabilities</h3>
            <h2>{scan_result.total_vulnerabilities}</h2>
        </div>
        """
        
        # Add severity breakdown
        for severity, count in scan_result.vulnerabilities_by_severity.items():
            if count > 0:
                color = severity_colors.get(severity, "#666")
                html_content += f"""
        <div class="summary-card">
            <h3 style="color: {color}">{severity.value.title()}</h3>
            <h2>{count}</h2>
        </div>
                """
        
        html_content += """
    </div>
    
    <h2>Vulnerabilities</h2>
        """
        
        # Add vulnerability details
        for vuln in scan_result.vulnerabilities:
            severity_class = f"severity-{vuln.severity.value}"
            html_content += f"""
    <div class="vulnerability {severity_class}">
        <h3>{vuln.message}</h3>
        <div class="location">{vuln.location.file}:{vuln.location.line}:{vuln.location.column}</div>
        <p>{vuln.description}</p>
        <p><strong>Severity:</strong> {vuln.severity.value.title()} | <strong>Confidence:</strong> {vuln.confidence:.2f}</p>
        {f'<div class="remediation"><strong>Remediation:</strong> {vuln.remediation}</div>' if vuln.remediation else ''}
    </div>
            """
        
        html_content += """
</body>
</html>
        """
        
        return html_content
    
    def _generate_markdown(self, scan_result: ScanResult) -> str:
        """
        Generate a Markdown report.
        
        Args:
            scan_result: The scan results to report
            
        Returns:
            Markdown-formatted report string
            
        Implementation Notes:
        - Should create readable markdown format
        - Should include proper headers and formatting
        - Should be suitable for documentation systems
        - Should include links and references where appropriate
        """
        # TODO: Implement comprehensive Markdown report generation
        # - Create well-structured markdown with headers
        # - Include tables for summary information
        # - Add code blocks for vulnerability details
        # - Include links to references and documentation
        
        md_content = f"""# MCP Scanner Security Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Files Scanned:** {scan_result.files_scanned}  
**Scan Duration:** {scan_result.scan_duration:.2f} seconds  

## Summary

**Total Vulnerabilities:** {scan_result.total_vulnerabilities}

### Vulnerabilities by Severity

"""
        
        # Add severity breakdown
        for severity, count in scan_result.vulnerabilities_by_severity.items():
            if count > 0:
                md_content += f"- **{severity.value.title()}:** {count}\\n"
        
        md_content += "\\n## Vulnerabilities\\n\\n"
        
        # Group vulnerabilities by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            severity_vulns = [v for v in scan_result.vulnerabilities if v.severity == severity]
            if severity_vulns:
                md_content += f"### {severity.value.title()} Severity\\n\\n"
                
                for vuln in severity_vulns:
                    md_content += f"""#### {vuln.message}

**Location:** `{vuln.location.file}:{vuln.location.line}:{vuln.location.column}`  
**Type:** {vuln.type.value}  
**Confidence:** {vuln.confidence:.2f}  

{vuln.description}

"""
                    if vuln.remediation:
                        md_content += f"**Remediation:** {vuln.remediation}\\n\\n"
                    
                    if vuln.references:
                        md_content += "**References:**\\n"
                        for ref in vuln.references:
                            md_content += f"- {ref}\\n"
                        md_content += "\\n"
        
        return md_content
    
    def _generate_text(self, scan_result: ScanResult) -> str:
        """
        Generate a plain text report.
        
        Args:
            scan_result: The scan results to report
            
        Returns:
            Plain text report string
            
        Implementation Notes:
        - Should create readable plain text format
        - Should use ASCII characters for formatting
        - Should be suitable for console output
        - Should include all essential information
        """
        # TODO: Implement comprehensive plain text report generation
        # - Use ASCII art for headers and separators
        # - Create readable columnar layout
        # - Include all vulnerability information
        # - Make it suitable for console and email
        
        text_content = f"""
MCP SCANNER SECURITY REPORT
{'=' * 50}

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Files Scanned: {scan_result.files_scanned}
Scan Duration: {scan_result.scan_duration:.2f} seconds

SUMMARY
{'-' * 20}

Total Vulnerabilities: {scan_result.total_vulnerabilities}

Vulnerabilities by Severity:
"""
        
        # Add severity breakdown
        for severity, count in scan_result.vulnerabilities_by_severity.items():
            if count > 0:
                text_content += f"  {severity.value.title()}: {count}\\n"
        
        text_content += f"\\n{'VULNERABILITIES':<50}\\n{'-' * 50}\\n\\n"
        
        # Add vulnerability details
        for i, vuln in enumerate(scan_result.vulnerabilities, 1):
            text_content += f"""[{i}] {vuln.message}
    Location: {vuln.location.file}:{vuln.location.line}:{vuln.location.column}
    Type: {vuln.type.value}
    Severity: {vuln.severity.value.title()}
    Confidence: {vuln.confidence:.2f}
    
    Description: {vuln.description}
    
"""
            if vuln.remediation:
                text_content += f"    Remediation: {vuln.remediation}\\n\\n"
            
            if vuln.references:
                text_content += "    References:\\n"
                for ref in vuln.references:
                    text_content += f"      - {ref}\\n"
                text_content += "\\n"
        
        return text_content