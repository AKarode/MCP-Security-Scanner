---
name: Analyzer Request
about: Request a new security analyzer for the MCP Scanner
title: '[ANALYZER] '
labels: ['analyzer', 'enhancement']
assignees: ''
---

## Analyzer Overview
<!-- Provide a clear description of the security analyzer you'd like to see implemented -->

## Vulnerability Type
<!-- What type of vulnerabilities should this analyzer detect? -->
- **Vulnerability Category**: [e.g., Injection, Authentication, Authorization]
- **CWE References**: [e.g., CWE-79, CWE-89]
- **OWASP Category**: [e.g., A03:2021 - Injection]

## Target Languages
<!-- Which programming languages should this analyzer support? -->
- [ ] Python
- [ ] JavaScript
- [ ] TypeScript
- [ ] Other: ___________

## Detection Patterns
<!-- Describe the patterns this analyzer should detect -->
1. Pattern 1: Description
2. Pattern 2: Description
3. Pattern 3: Description

## Example Vulnerable Code
<!-- Provide examples of code that should be flagged -->
```python
# Example vulnerable code here
```

## Example Safe Code
<!-- Provide examples of code that should NOT be flagged -->
```python
# Example safe code here
```

## Severity Assessment
<!-- What severity levels should this analyzer typically assign? -->
- **Typical Severity**: [Critical/High/Medium/Low]
- **Confidence Level**: [High/Medium/Low]

## Implementation Requirements
- [ ] AST analysis required
- [ ] Data flow analysis required
- [ ] Pattern matching sufficient
- [ ] External tool integration needed

## Testing Requirements
- [ ] Unit tests for detection logic
- [ ] Integration tests with real code
- [ ] Performance tests
- [ ] False positive tests

## References
<!-- Include links to security advisories, documentation, or research -->
- Reference 1:
- Reference 2:
- Reference 3:

## Configuration Options
<!-- What configuration options should this analyzer support? -->
- Option 1: Description
- Option 2: Description

## Priority Justification
<!-- Why is this analyzer important? -->

## Additional Context
<!-- Any other relevant information -->