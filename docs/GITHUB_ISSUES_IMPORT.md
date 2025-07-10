# GitHub Issues Import Guide

This document provides ready-to-import GitHub issues based on the implementation timeline. Each issue can be copied and pasted directly into GitHub Issues.

## How to Import Issues

1. Go to your GitHub repository
2. Navigate to the "Issues" tab
3. Click "New Issue"
4. Copy and paste the content from the sections below
5. Adjust labels, assignees, and milestones as needed

## Phase 0 Issues

### Issue #1: Technology Stack Research and Decision

**Labels**: `research`, `architecture`, `phase-0`  
**Milestone**: Phase 0 - Research & Architecture  
**Assignee**: Lead Developer  

**Title**: [PHASE-0] Technology Stack Research and Decision

**Description**:
Research and finalize the technology stack for the MCP Scanner, comparing different approaches for parsing, analysis, and reporting.

**Tasks**:
- [ ] Research Python AST parsing libraries (ast, tree-sitter, etc.)
- [ ] Evaluate JavaScript/TypeScript parsing options (tree-sitter, babel, etc.)
- [ ] Compare secret detection approaches (entropy, regex, ML)
- [ ] Research CI/CD integration patterns
- [ ] Evaluate report generation libraries (Jinja2, WeasyPrint, etc.)

**Acceptance Criteria**:
- [ ] Decision matrix created comparing all options
- [ ] ADR document created for each major decision
- [ ] Performance benchmarks for parsing large files
- [ ] Memory usage analysis for different approaches

**Effort Estimate**: 16 hours

---

### Issue #2: Development Environment Setup

**Labels**: `setup`, `development`, `phase-0`  
**Milestone**: Phase 0 - Research & Architecture  
**Assignee**: Any Developer  

**Title**: [PHASE-0] Development Environment Setup

**Description**:
Set up the complete development environment with all necessary tools and dependencies.

**Tasks**:
- [ ] Set up Python virtual environment
- [ ] Install all dependencies from requirements-dev.txt
- [ ] Configure pre-commit hooks
- [ ] Set up testing framework (pytest)
- [ ] Configure code quality tools (black, isort, flake8, mypy)
- [ ] Set up documentation generation (Sphinx)

**Acceptance Criteria**:
- [ ] All tests pass: `pytest`
- [ ] Code formatting works: `black --check src/`
- [ ] Type checking passes: `mypy src/`
- [ ] Pre-commit hooks installed and working
- [ ] Documentation builds successfully

**Effort Estimate**: 8 hours

---

### Issue #3: Create Architecture Decision Records

**Labels**: `documentation`, `architecture`, `phase-0`  
**Milestone**: Phase 0 - Research & Architecture  
**Assignee**: Lead Developer  

**Title**: [PHASE-0] Create Architecture Decision Records

**Description**:
Document all major architectural decisions with detailed ADRs following the ADR template.

**Tasks**:
- [ ] ADR-001: Programming Language Choice (Python)
- [ ] ADR-002: Parser Technology Selection
- [ ] ADR-003: Plugin Architecture Design
- [ ] ADR-004: Report Generation Strategy
- [ ] ADR-005: CI/CD Integration Approach
- [ ] ADR-006: Performance vs Accuracy Trade-offs

**Acceptance Criteria**:
- [ ] All ADRs follow consistent template
- [ ] Each ADR includes context, options, decision, and consequences
- [ ] ADRs are reviewed and approved by team
- [ ] ADRs are committed to docs/adr/ directory

**Dependencies**: Issue #1  
**Effort Estimate**: 12 hours

---

### Issue #4: Validate Core Architecture with Proof of Concept

**Labels**: `poc`, `architecture`, `phase-0`  
**Milestone**: Phase 0 - Research & Architecture  
**Assignee**: Lead Developer  

**Title**: [PHASE-0] Validate Core Architecture with Proof of Concept

**Description**:
Build a minimal proof of concept to validate the core architecture works end-to-end.

**Tasks**:
- [ ] Implement basic file discovery
- [ ] Create simple Python AST parser
- [ ] Build one basic analyzer (secrets detection)
- [ ] Generate simple JSON report
- [ ] Verify plugin architecture works
- [ ] Test performance on medium-sized codebase

**Acceptance Criteria**:
- [ ] POC can scan a real Python project
- [ ] POC finds at least one type of vulnerability
- [ ] POC generates valid JSON report
- [ ] POC completes scan in under 30 seconds for 1000 files
- [ ] Memory usage stays under 500MB

**Dependencies**: Issue #1, Issue #2  
**Effort Estimate**: 20 hours

---

## Phase 1 Issues

### Issue #5: Implement File Discovery System

**Labels**: `core`, `file-discovery`, `phase-1`  
**Milestone**: Phase 1 - MVP Core Scanner  
**Assignee**: Backend Developer  

**Title**: [PHASE-1] Implement File Discovery System

**Description**:
Implement the file discovery system that finds files to scan based on include/exclude patterns.

**Tasks**:
- [ ] Implement `discover_files()` in ScanEngine
- [ ] Support glob patterns for include/exclude
- [ ] Handle symlinks appropriately
- [ ] Respect max file size limits
- [ ] Add progress tracking for large directories
- [ ] Implement file type detection

**Acceptance Criteria**:
- [ ] Can discover files using glob patterns
- [ ] Respects include/exclude patterns correctly
- [ ] Handles large directories (>10k files) efficiently
- [ ] Provides progress feedback
- [ ] Skips binary files and respects size limits
- [ ] Unit tests achieve 90% coverage

**Dependencies**: Issue #4  
**Effort Estimate**: 16 hours

---

### Issue #6: Complete Python Parser Implementation

**Labels**: `parser`, `python`, `phase-1`  
**Milestone**: Phase 1 - MVP Core Scanner  
**Assignee**: Parser Developer  

**Title**: [PHASE-1] Complete Python Parser Implementation

**Description**:
Complete the Python parser implementation with full AST extraction and metadata.

**Tasks**:
- [ ] Implement encoding detection
- [ ] Handle Python syntax errors gracefully
- [ ] Extract comprehensive metadata (imports, functions, classes)
- [ ] Support Python 3.9+ syntax features
- [ ] Add source code line mapping
- [ ] Implement caching for parsed files

**Acceptance Criteria**:
- [ ] Can parse all valid Python files
- [ ] Handles encoding issues gracefully
- [ ] Extracts all required metadata
- [ ] Provides accurate line/column information
- [ ] Caches parsed results for performance
- [ ] Unit tests cover edge cases

**Dependencies**: Issue #4  
**Effort Estimate**: 20 hours

---

## Bulk Import Script

You can also use this Python script to bulk import issues:

```python
#!/usr/bin/env python3
"""
Bulk import GitHub issues from the implementation timeline.
Requires PyGithub: pip install PyGithub
"""

from github import Github
import os

# Set up GitHub client
token = os.environ.get('GITHUB_TOKEN')
repo_name = "your-username/mcp-scanner"  # Update this

g = Github(token)
repo = g.get_repo(repo_name)

# Phase 0 Issues
issues = [
    {
        "title": "[PHASE-0] Technology Stack Research and Decision",
        "body": """Research and finalize the technology stack for the MCP Scanner.

**Tasks**:
- [ ] Research Python AST parsing libraries
- [ ] Evaluate JavaScript/TypeScript parsing options
- [ ] Compare secret detection approaches
- [ ] Research CI/CD integration patterns
- [ ] Evaluate report generation libraries

**Acceptance Criteria**:
- [ ] Decision matrix created
- [ ] ADR documents created
- [ ] Performance benchmarks completed
- [ ] Memory usage analysis completed

**Effort**: 16 hours""",
        "labels": ["research", "architecture", "phase-0"]
    },
    # Add more issues here...
]

# Create issues
for issue_data in issues:
    issue = repo.create_issue(
        title=issue_data["title"],
        body=issue_data["body"],
        labels=issue_data["labels"]
    )
    print(f"Created issue #{issue.number}: {issue.title}")
```

## Labels to Create

Before importing issues, create these labels in your GitHub repository:

### Phase Labels
- `phase-0` (color: #d73a4a)
- `phase-1` (color: #0075ca)
- `phase-2` (color: #cfd3d7)
- `phase-3` (color: #a2eeef)
- `phase-4` (color: #7057ff)
- `phase-5` (color: #008672)

### Component Labels
- `core` (color: #d93f0b)
- `analyzer` (color: #fbca04)
- `parser` (color: #0e8a16)
- `cli` (color: #1d76db)
- `reporting` (color: #f9d0c4)

### Type Labels
- `research` (color: #5319e7)
- `implementation` (color: #006b75)
- `documentation` (color: #0052cc)
- `testing` (color: #bfd4f2)
- `performance` (color: #e99695)

### Priority Labels
- `priority-high` (color: #d73a4a)
- `priority-medium` (color: #fbca04)
- `priority-low` (color: #0e8a16)

## Milestones to Create

Create these milestones in your GitHub repository:

1. **Phase 0 - Research & Architecture** (1 week)
2. **Phase 1 - MVP Core Scanner** (1 week)
3. **Phase 2 - MCP-Specific Analyzers** (1 week)
4. **Phase 3 - Reporting & CI Integration** (1 week)
5. **Phase 4 - Advanced Analysis Features** (2 weeks)
6. **Phase 5 - Performance & Production Ready** (1 week)

## Project Board Setup

Consider setting up a GitHub Project board with these columns:
- **Backlog** - Issues not yet started
- **In Progress** - Currently being worked on
- **Review** - Completed and under review
- **Done** - Completed and merged

This provides a kanban-style view of the implementation progress.