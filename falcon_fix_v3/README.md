# FalconFix v3 - Intelligent Dependency Version Analyzer

## Overview
This system analyzes vulnerable dependencies and recommends the best fixed version using:
1. Dependency graph analysis
2. JFrog scan results (vulnerable → fixed versions)
3. Changelog data analysis
4. LLM-powered reasoning with chain-of-thought

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INPUT                               │
│  - Dependency Tree (from Maven/Gradle)                          │
│  - JFrog Scan Results (vulnerable versions + fixes)             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DEPENDENCY GRAPH BUILDER                      │
│  - Converts tree → graph with metadata                          │
│  - Calculates: depth, centrality, direct/transitive             │
│  - Identifies: parent/child relationships                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CHANGELOG FETCHER                             │
│  Primary: Spring Boot API endpoint                              │
│  Fallback: Playwright browser scraping                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    LLM AGENT (OpenAI)                            │
│  - Receives: dependency graph + JFrog scan + changelogs         │
│  - Uses: Chain-of-thought reasoning                             │
│  - Outputs: Recommended version + detailed justification        │
└─────────────────────────────────────────────────────────────────┘
```

## Why NOT Multi-Agent (CrewAI)?

This is a **single-agent workflow** because:
- All tasks are sequential (graph → changelog → analyze → decide)
- No parallel independent agents needed
- One "brain" making all decisions
- CrewAI adds unnecessary complexity for this use case

## Why NOT LangGraph?

LangGraph is great for:
- Complex branching workflows
- Cycles and loops in decision making
- Multi-step planning with backtracking

Our workflow is **linear**: Input → Process → Analyze → Output
No complex state machines needed.

## Why OpenAI Agents SDK (or simple function calling)?

✅ Perfect fit because:
- Single agent with tools
- Linear workflow
- Tools for: fetching changelogs, parsing graphs
- Simple, maintainable code
- Easy to debug and extend

## Files

- `dependency_graph.py` - Graph utilities
- `changelog_fetcher.py` - API + Playwright fallback
- `version_analyzer.py` - Main agent logic
- `main.py` - Entry point
- `requirements.txt` - Dependencies

