"""
version_analyzer.py
===================
The MAIN LLM Agent that analyzes dependencies and recommends versions.

ARCHITECTURE DECISION: Single Agent with Tools (NOT Multi-Agent)
================================================================

WHY NOT CREWAI (Multi-Agent)?
-----------------------------
CrewAI is designed for scenarios where you have:
- Multiple INDEPENDENT agents with different roles
- Agents that need to COLLABORATE and DEBATE
- Complex workflows where agents hand off work to each other

Our use case is SEQUENTIAL and SINGLE-MINDED:
1. Parse dependency graph (deterministic)
2. Fetch changelogs (tool call)
3. Analyze and decide (ONE decision maker)

Using CrewAI would be like hiring 5 people to do one person's job.
It adds complexity without benefit.

WHY NOT LANGGRAPH?
------------------
LangGraph excels at:
- Complex state machines
- Branching and looping workflows
- Human-in-the-loop approvals
- Long-running processes with checkpoints

Our workflow is LINEAR:
Input → Process → Analyze → Output

No cycles, no complex branching, no human approval needed.
LangGraph would be over-engineering.

WHY OPENAI FUNCTION CALLING (or Agents SDK)?
--------------------------------------------
Perfect fit because:
✅ Single agent making all decisions
✅ Tools for specific tasks (fetch changelog, query graph)
✅ Simple, maintainable code
✅ Easy to debug
✅ Well-documented
✅ Production-ready

CHAIN OF THOUGHT REASONING
==========================
We structure the prompt to force the LLM to reason step-by-step:

1. UNDERSTAND the vulnerability
   - What is vulnerable?
   - What's the impact in our dependency graph?

2. ANALYZE the options
   - List all fixed versions
   - For each: check breaking changes, compatibility

3. DECIDE using top-down approach
   - Start with highest version
   - Check compatibility
   - If not compatible, go to next lower
   - Explain WHY at each step

4. JUSTIFY the recommendation
   - Why this version?
   - What are the risks?
   - What testing is needed?
"""

import os
import json
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from openai import OpenAI

from dependency_graph import DependencyGraph, parse_dependency_tree
from changelog_fetcher import ChangelogFetcher, ChangelogEntry


# =============================================================================
# CONFIGURATION
# =============================================================================

# OpenAI API key
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Model to use
MODEL = "gpt-4o"  # or "gpt-4-turbo" or "gpt-3.5-turbo"

# Maximum tokens for response
MAX_TOKENS = 4000


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class JFrogVulnerability:
    """
    Represents a vulnerability from JFrog scan.
    
    Attributes:
        vulnerable_ga: The vulnerable group:artifact
        vulnerable_version: The vulnerable version
        fixed_versions: List of versions that fix this vulnerability
        cve_id: CVE identifier if available
        severity: CRITICAL, HIGH, MEDIUM, LOW
        description: Description of the vulnerability
    """
    vulnerable_ga: str
    vulnerable_version: str
    fixed_versions: List[str]
    cve_id: Optional[str] = None
    severity: str = "UNKNOWN"
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerable_ga": self.vulnerable_ga,
            "vulnerable_version": self.vulnerable_version,
            "fixed_versions": self.fixed_versions,
            "cve_id": self.cve_id,
            "severity": self.severity,
            "description": self.description,
        }


@dataclass
class VersionRecommendation:
    """
    The output of the version analyzer.
    
    Attributes:
        recommended_version: The version to upgrade to
        reasoning: Detailed chain-of-thought reasoning
        risk_level: LOW, MEDIUM, HIGH
        breaking_changes: List of breaking changes to watch for
        testing_recommendations: What to test after upgrade
        fallback_versions: Alternative versions if recommended fails
    """
    recommended_version: str
    reasoning: str
    risk_level: str
    breaking_changes: List[str]
    testing_recommendations: List[str]
    fallback_versions: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "recommended_version": self.recommended_version,
            "reasoning": self.reasoning,
            "risk_level": self.risk_level,
            "breaking_changes": self.breaking_changes,
            "testing_recommendations": self.testing_recommendations,
            "fallback_versions": self.fallback_versions,
        }


# =============================================================================
# THE SYSTEM PROMPT - This is the "brain" of the agent
# =============================================================================

SYSTEM_PROMPT = """You are an expert Java/Spring dependency version analyzer.

YOUR ROLE:
You help developers choose the BEST fixed version for vulnerable dependencies.
You analyze dependency graphs, changelogs, and compatibility to make recommendations.

YOUR APPROACH - TOP-DOWN VERSION SELECTION:
1. Start with the HIGHEST fixed version
2. Check if it's compatible with the project
3. If yes → recommend it (newer = more fixes = better)
4. If no → explain why and try the next lower version
5. Continue until you find a compatible version

CHAIN OF THOUGHT REASONING:
You MUST think through each decision step by step. For each version:

STEP 1 - GRAPH ANALYSIS:
- Where is this dependency in the graph?
- What depends on it? (children)
- What does it depend on? (parents)
- Is it a direct or transitive dependency?
- What's the impact score?

STEP 2 - CHANGELOG ANALYSIS:
- Are there breaking changes?
- What APIs changed?
- Are there migration guides?
- What's the release date? (newer = potentially less tested)

STEP 3 - COMPATIBILITY CHECK:
- Does this version work with our Spring Boot version?
- Does it conflict with other dependencies?
- Are there Java version requirements?

STEP 4 - DECISION:
- IF compatible: Recommend this version
- IF not compatible: Explain why and try next lower version

OUTPUT FORMAT:
Always structure your response as JSON with these fields:
{
    "recommended_version": "X.Y.Z",
    "reasoning": "Step-by-step explanation of your decision...",
    "risk_level": "LOW|MEDIUM|HIGH",
    "breaking_changes": ["list", "of", "breaking", "changes"],
    "testing_recommendations": ["what", "to", "test"],
    "fallback_versions": ["alternative", "versions"]
}

IMPORTANT RULES:
1. NEVER recommend a version without checking the changelog
2. ALWAYS prefer the highest compatible version (top-down)
3. ALWAYS explain your reasoning step by step
4. If you can't determine compatibility, say so and suggest testing
5. Consider the impact score - high impact = more careful analysis needed
"""


# =============================================================================
# TOOL DEFINITIONS for OpenAI Function Calling
# =============================================================================

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_dependency_info",
            "description": "Get detailed information about a dependency from the graph, including its position, impact score, and relationships.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ga": {
                        "type": "string",
                        "description": "The group:artifact identifier (e.g., 'org.springframework:spring-core')"
                    }
                },
                "required": ["ga"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_changelog",
            "description": "Fetch the changelog for a specific version of a dependency. Returns breaking changes, bug fixes, and security fixes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ga": {
                        "type": "string",
                        "description": "The group:artifact identifier"
                    },
                    "version": {
                        "type": "string",
                        "description": "The version to get changelog for"
                    }
                },
                "required": ["ga", "version"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_version_compatibility",
            "description": "Check if a version is compatible with the current project based on dependency constraints.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ga": {
                        "type": "string",
                        "description": "The group:artifact identifier"
                    },
                    "version": {
                        "type": "string",
                        "description": "The version to check"
                    }
                },
                "required": ["ga", "version"]
            }
        }
    }
]


# =============================================================================
# VERSION ANALYZER AGENT
# =============================================================================

class VersionAnalyzer:
    """
    The main LLM-powered version analyzer.
    
    USAGE:
    ------
    analyzer = VersionAnalyzer(dependency_graph)
    
    # Analyze a single vulnerability
    recommendation = await analyzer.analyze_vulnerability(
        JFrogVulnerability(
            vulnerable_ga="org.apache.tomcat.embed:tomcat-embed-core",
            vulnerable_version="10.1.20",
            fixed_versions=["10.1.25", "10.1.24", "10.1.23"],
            severity="HIGH"
        )
    )
    
    print(recommendation.recommended_version)
    print(recommendation.reasoning)
    """
    
    def __init__(
        self, 
        dependency_graph: DependencyGraph,
        openai_api_key: Optional[str] = None
    ):
        """
        Initialize the analyzer.
        
        Args:
            dependency_graph: The parsed dependency graph
            openai_api_key: OpenAI API key (or use OPENAI_API_KEY env var)
        """
        self.graph = dependency_graph
        self.client = OpenAI(api_key=openai_api_key or OPENAI_API_KEY)
        self.changelog_fetcher = ChangelogFetcher()
        
        # Cache for changelogs (avoid re-fetching)
        self._changelog_cache: Dict[str, Dict[str, Any]] = {}
    
    async def analyze_vulnerability(
        self, 
        vulnerability: JFrogVulnerability
    ) -> VersionRecommendation:
        """
        Analyze a vulnerability and recommend the best fixed version.
        
        This is the MAIN METHOD that orchestrates:
        1. Building context for the LLM
        2. Calling the LLM with tools
        3. Processing tool calls
        4. Getting the final recommendation
        """
        # Step 1: Build the context
        context = self._build_context(vulnerability)
        
        # Step 2: Pre-fetch changelogs for all fixed versions
        # This makes tool calls faster
        await self._prefetch_changelogs(
            vulnerability.vulnerable_ga,
            vulnerability.fixed_versions
        )
        
        # Step 3: Call the LLM
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": context}
        ]
        
        # Agentic loop: keep calling until we get a final answer
        max_iterations = 10  # Safety limit
        for _ in range(max_iterations):
            response = self.client.chat.completions.create(
                model=MODEL,
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
                max_tokens=MAX_TOKENS,
            )
            
            message = response.choices[0].message
            
            # If no tool calls, we have the final answer
            if not message.tool_calls:
                return self._parse_response(message.content, vulnerability)
            
            # Process tool calls
            messages.append(message)
            
            for tool_call in message.tool_calls:
                result = await self._execute_tool(tool_call)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result)
                })
        
        # If we hit max iterations, return a safe default
        return self._default_recommendation(vulnerability)
    
    def _build_context(self, vulnerability: JFrogVulnerability) -> str:
        """
        Build the context string for the LLM.
        
        This includes:
        - The vulnerability details
        - The dependency's position in the graph
        - The available fixed versions
        - Instructions for analysis
        """
        # Get dependency info from graph
        dep_info = self.graph.get_dependency_info(vulnerability.vulnerable_ga)
        
        context = f"""
VULNERABILITY ANALYSIS REQUEST
==============================

VULNERABLE DEPENDENCY:
- Group:Artifact: {vulnerability.vulnerable_ga}
- Current Version: {vulnerability.vulnerable_version}
- Severity: {vulnerability.severity}
- CVE: {vulnerability.cve_id or 'Not specified'}
- Description: {vulnerability.description or 'Not provided'}

AVAILABLE FIXED VERSIONS (sorted highest to lowest):
{json.dumps(sorted(vulnerability.fixed_versions, reverse=True), indent=2)}

DEPENDENCY GRAPH POSITION:
{json.dumps(dep_info, indent=2) if dep_info else "Not found in dependency graph"}

PROJECT CONTEXT:
- Root Project: {self.graph.root_project}
- Total Dependencies: {len(self.graph.nodes)}

YOUR TASK:
1. Analyze each fixed version starting from the HIGHEST
2. Use the tools to get changelog and compatibility info
3. Apply TOP-DOWN selection: pick the highest compatible version
4. Provide detailed reasoning for your choice
5. Return your recommendation in the specified JSON format

Remember: Think step by step. Check each version. Explain your reasoning.
"""
        return context
    
    async def _prefetch_changelogs(
        self, 
        ga: str, 
        versions: List[str]
    ) -> None:
        """
        Pre-fetch changelogs to speed up tool calls.
        """
        async with self.changelog_fetcher:
            for version in versions:
                cache_key = f"{ga}:{version}"
                if cache_key not in self._changelog_cache:
                    changelog = await self.changelog_fetcher.fetch(ga, version)
                    if changelog:
                        self._changelog_cache[cache_key] = changelog.to_dict()
    
    async def _execute_tool(self, tool_call) -> Dict[str, Any]:
        """
        Execute a tool call and return the result.
        """
        name = tool_call.function.name
        args = json.loads(tool_call.function.arguments)
        
        if name == "get_dependency_info":
            return self._tool_get_dependency_info(args["ga"])
        
        elif name == "get_changelog":
            return await self._tool_get_changelog(args["ga"], args["version"])
        
        elif name == "check_version_compatibility":
            return self._tool_check_compatibility(args["ga"], args["version"])
        
        else:
            return {"error": f"Unknown tool: {name}"}
    
    def _tool_get_dependency_info(self, ga: str) -> Dict[str, Any]:
        """
        Tool: Get dependency info from graph.
        """
        info = self.graph.get_dependency_info(ga)
        if info:
            return info
        return {"error": f"Dependency {ga} not found in graph"}
    
    async def _tool_get_changelog(self, ga: str, version: str) -> Dict[str, Any]:
        """
        Tool: Get changelog for a version.
        """
        cache_key = f"{ga}:{version}"
        
        # Check cache first
        if cache_key in self._changelog_cache:
            return self._changelog_cache[cache_key]
        
        # Fetch if not cached
        async with self.changelog_fetcher:
            changelog = await self.changelog_fetcher.fetch(ga, version)
            if changelog:
                result = changelog.to_dict()
                self._changelog_cache[cache_key] = result
                return result
        
        return {
            "version": version,
            "error": "Changelog not found",
            "note": "Could not fetch changelog. Consider checking manually."
        }
    
    def _tool_check_compatibility(self, ga: str, version: str) -> Dict[str, Any]:
        """
        Tool: Check version compatibility.
        
        This is a simplified check. In a real system, you would:
        - Check Maven/Gradle dependency constraints
        - Check Spring Boot BOM compatibility
        - Check Java version requirements
        """
        dep_info = self.graph.get_dependency_info(ga)
        if not dep_info:
            return {
                "compatible": "unknown",
                "reason": "Dependency not in graph, cannot determine compatibility"
            }
        
        # Get parent dependencies to check constraints
        parents = dep_info.get("parents", [])
        
        # Simplified compatibility check
        # In reality, you'd check version ranges, BOMs, etc.
        result = {
            "ga": ga,
            "version": version,
            "compatible": "likely",  # We can't be 100% sure without actual resolution
            "parents": parents,
            "notes": [
                f"This dependency has {len(parents)} parent(s)",
                "Recommend testing after upgrade",
                "Check for any version constraints in parent POMs"
            ]
        }
        
        # Add warnings based on version jump
        current_version = dep_info.get("version", "")
        if current_version:
            result["current_version"] = current_version
            result["notes"].append(f"Upgrading from {current_version} to {version}")
        
        return result
    
    def _parse_response(
        self, 
        content: str, 
        vulnerability: JFrogVulnerability
    ) -> VersionRecommendation:
        """
        Parse the LLM response into a VersionRecommendation.
        """
        try:
            # Try to extract JSON from the response
            # LLM might wrap it in markdown code blocks
            json_match = content
            if "```json" in content:
                json_match = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                json_match = content.split("```")[1].split("```")[0]
            
            data = json.loads(json_match)
            
            return VersionRecommendation(
                recommended_version=data.get("recommended_version", vulnerability.fixed_versions[0]),
                reasoning=data.get("reasoning", "No reasoning provided"),
                risk_level=data.get("risk_level", "MEDIUM"),
                breaking_changes=data.get("breaking_changes", []),
                testing_recommendations=data.get("testing_recommendations", []),
                fallback_versions=data.get("fallback_versions", vulnerability.fixed_versions[1:3])
            )
            
        except (json.JSONDecodeError, IndexError, KeyError) as e:
            # If parsing fails, return a safe default with the raw reasoning
            return VersionRecommendation(
                recommended_version=vulnerability.fixed_versions[0],
                reasoning=f"LLM Response (unparsed):\n{content}",
                risk_level="MEDIUM",
                breaking_changes=[],
                testing_recommendations=["Full regression test recommended"],
                fallback_versions=vulnerability.fixed_versions[1:3] if len(vulnerability.fixed_versions) > 1 else []
            )
    
    def _default_recommendation(
        self, 
        vulnerability: JFrogVulnerability
    ) -> VersionRecommendation:
        """
        Return a safe default recommendation if analysis fails.
        """
        return VersionRecommendation(
            recommended_version=vulnerability.fixed_versions[0],
            reasoning="Analysis could not complete. Defaulting to highest fixed version.",
            risk_level="HIGH",
            breaking_changes=["Unknown - manual review required"],
            testing_recommendations=["Full regression test required", "Manual changelog review recommended"],
            fallback_versions=vulnerability.fixed_versions[1:3] if len(vulnerability.fixed_versions) > 1 else []
        )


# =============================================================================
# BATCH ANALYZER - For multiple vulnerabilities
# =============================================================================

async def analyze_all_vulnerabilities(
    dependency_graph: DependencyGraph,
    vulnerabilities: List[JFrogVulnerability]
) -> Dict[str, VersionRecommendation]:
    """
    Analyze multiple vulnerabilities and return recommendations for each.
    
    USAGE:
    ------
    results = await analyze_all_vulnerabilities(graph, vulnerabilities)
    for ga, recommendation in results.items():
        print(f"{ga}: Upgrade to {recommendation.recommended_version}")
    """
    analyzer = VersionAnalyzer(dependency_graph)
    results = {}
    
    for vuln in vulnerabilities:
        print(f"Analyzing: {vuln.vulnerable_ga}...")
        recommendation = await analyzer.analyze_vulnerability(vuln)
        results[vuln.vulnerable_ga] = recommendation
        print(f"  → Recommended: {recommendation.recommended_version}")
    
    return results


# =============================================================================
# TESTING
# =============================================================================

if __name__ == "__main__":
    async def test():
        print("Testing Version Analyzer...")
        print("=" * 60)
        
        # Sample dependency tree
        tree_text = """
com.random-x:part-finder-service-api:1.2.39-SNAPSHOT
├── org.springframework.boot:spring-boot-starter-tomcat:3.5.3
│   ├── org.apache.tomcat.embed:tomcat-embed-core:10.1.42
│   │   ├── jakarta.servlet:jakarta.servlet-api:6.0.0
│   │   └── org.apache.tomcat.embed:tomcat-embed-websocket:10.1.42
├── org.springframework.boot:spring-boot-starter-web:3.5.3
│   ├── org.springframework.boot:spring-boot:3.5.3
│   │   └── org.springframework:spring-core:6.2.8
"""
        
        # Parse the dependency graph
        graph = parse_dependency_tree(tree_text)
        print(f"Parsed {len(graph.nodes)} dependencies")
        
        # Create a test vulnerability
        vuln = JFrogVulnerability(
            vulnerable_ga="org.apache.tomcat.embed:tomcat-embed-core",
            vulnerable_version="10.1.42",
            fixed_versions=["10.1.45", "10.1.44", "10.1.43"],
            cve_id="CVE-2024-XXXX",
            severity="HIGH",
            description="Remote code execution vulnerability in Tomcat"
        )
        
        # Analyze
        print(f"\nAnalyzing vulnerability: {vuln.vulnerable_ga}")
        print(f"Fixed versions available: {vuln.fixed_versions}")
        
        analyzer = VersionAnalyzer(graph)
        recommendation = await analyzer.analyze_vulnerability(vuln)
        
        print("\n" + "=" * 60)
        print("RECOMMENDATION:")
        print(f"  Version: {recommendation.recommended_version}")
        print(f"  Risk Level: {recommendation.risk_level}")
        print(f"\nReasoning:\n{recommendation.reasoning}")
        print(f"\nBreaking Changes: {recommendation.breaking_changes}")
        print(f"Testing: {recommendation.testing_recommendations}")
        print(f"Fallbacks: {recommendation.fallback_versions}")
    
    asyncio.run(test())

