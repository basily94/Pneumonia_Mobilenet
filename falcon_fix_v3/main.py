"""
main.py
=======
Entry point for the FalconFix v3 Version Analyzer.

This file demonstrates the COMPLETE WORKFLOW:
1. Parse dependency tree → Dependency Graph
2. Load JFrog scan results → Vulnerabilities
3. Analyze each vulnerability → Recommendations
4. Output results in a structured format

USAGE:
------
# Basic usage
python main.py

# With custom dependency tree file
python main.py --tree-file my_tree.txt

# With JFrog scan JSON
python main.py --jfrog-scan scan_results.json
"""

import asyncio
import argparse
import json
import os
from typing import List, Dict, Any

from dependency_graph import parse_dependency_tree, DependencyGraph
from version_analyzer import (
    VersionAnalyzer, 
    JFrogVulnerability, 
    VersionRecommendation,
    analyze_all_vulnerabilities
)
from upgrade_strategy import (
    UpgradeStrategyAnalyzer,
    UpgradeStrategy,
    UpgradeRecommendation as StrategyRecommendation,
    analyze_upgrade
)


# =============================================================================
# SAMPLE DATA - The dependency tree you provided
# =============================================================================

SAMPLE_DEPENDENCY_TREE = """
com.random-x:part-finder-service-api:1.2.39-SNAPSHOT
├── org.springframework.boot:spring-boot-starter-tomcat:3.5.3
│   ├── org.apache.tomcat.embed:tomcat-embed-core:10.1.42
│   │   ├── jakarta.servlet:jakarta.servlet-api:6.0.0
│   │   ├── org.apache.tomcat.embed:tomcat-embed-el:10.1.42
│   │   └── org.apache.tomcat.embed:tomcat-embed-websocket:10.1.42
│
├── org.springframework.boot:spring-boot-starter-web:3.5.3
│   ├── org.springframework.boot:spring-boot-starter:3.5.3
│   │   ├── org.springframework.boot:spring-boot:3.5.3
│   │   │   └── org.springframework:spring-core:6.2.8
│   │   │       └── org.springframework:spring-jcl:6.2.8
│   │   ├── org.springframework.boot:spring-boot-autoconfigure:3.5.3
│   │   └── org.springframework.boot:spring-boot-starter-logging:3.5.3
│   │       ├── ch.qos.logback:logback-classic:1.5.3
│   │       │   └── ch.qos.logback:logback-core:1.5.3
│   │       ├── org.apache.logging.log4j:log4j-to-slf4j:2.23.1
│   │       └── org.slf4j:jul-to-slf4j:2.0.13
│   ├── org.springframework:spring-web:6.2.8
│   │   └── org.springframework:spring-beans:6.2.8
│   └── org.springframework:spring-webmvc:6.2.8
│       ├── org.springframework:spring-aop:6.2.8
│       ├── org.springframework:spring-context:6.2.8
│       │   └── org.springframework:spring-expression:6.2.8
│       └── org.springframework:spring-core:6.2.8
│
├── org.springframework.boot:spring-boot-starter-json:3.5.3
│   ├── com.fasterxml.jackson.core:jackson-databind:2.19.1
│   ├── com.fasterxml.jackson.core:jackson-annotations:2.19.1
│   ├── com.fasterxml.jackson.core:jackson-core:2.19.1
│   ├── com.fasterxml.jackson.datatype:jackson-datatype-jdk8:2.19.1
│   ├── com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.19.1
│   ├── com.fasterxml.jackson.module:jackson-module-parameter-names:2.19.1
│   └── com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.19.1
│
├── org.springframework.boot:spring-boot-starter-validation:3.5.3
│   ├── org.hibernate.validator:hibernate-validator:8.0.2.Final
│   │   ├── jakarta.validation:jakarta.validation-api:3.0.2
│   │   ├── org.jboss.logging:jboss-logging:3.6.1.Final
│   │   └── com.fasterxml.jackson:classmate:1.7.0
│   └── org.springframework:spring-context:6.2.8
│
├── org.springframework.boot:spring-boot-starter-data-jpa:3.5.3
│   ├── org.springframework.data:spring-data-jpa:3.5.3
│   │   └── org.springframework.data:spring-data-commons:3.5.3
│   ├── org.hibernate.orm:hibernate-core:6.6.9.Final
│   │   ├── jakarta.persistence:jakarta.persistence-api:3.1.0
│   │   └── jakarta.transaction:jakarta.transaction-api:2.0.1
│   └── org.springframework:spring-jdbc:6.2.8
│
├── org.springframework.boot:spring-boot-starter-actuator:3.5.3
│   └── io.micrometer:micrometer-core:1.15.3
│       ├── io.micrometer:micrometer-commons:1.15.3
│       └── io.micrometer:micrometer-observation:1.15.3
│
├── io.micrometer:micrometer-core:1.13.5
│   ├── org.hdrhistogram:HdrHistogram:2.2.2
│   └── org.latencyutils:LatencyUtils:2.0.3
│
├── mysql:mysql-connector-java:5.1.47
│
├── com.random-x.platform.data:random-x-cassandra:4.19.0.3
│   ├── com.random-x.platform.data:random-x-dxs:0.0.17
│   └── com.random-x.platform.data:daf-basic-util:1.2.1
│
├── com.random-x.platform.data:sam-utils-lib:1.2.1
├── com.random-x.platform.data:metric-server:3.1.1
│
├── io.netty:netty-buffer:4.1.122.Final
├── io.netty:netty-transport:4.1.122.Final
├── io.netty:netty-handler:4.1.122.Final
│   ├── io.netty:netty-codec:4.1.122.Final
│   └── io.netty:netty-transport-native-unix-common:4.1.122.Final
│
├── org.apache.cassandra:java-driver-core:4.19.0
│   ├── com.datastax.oss:native-protocol:1.5.1
│   ├── org.apache.cassandra:java-driver-guava-shaded:4.19.0
│   └── com.typesafe:config:1.4.1
│
├── com.hazelcast:hazelcast:4.2.6
├── com.hazelcast:hazelcast-kubernetes:2.2
│
├── org.ehcache:ehcache:3.10.8
│   └── org.glassfish.jaxb:jaxb-runtime:4.0.5
│
├── org.apache.logging.log4j:log4j-api:2.24.3
├── org.apache.logging.log4j:log4j-core:2.24.3
│   └── org.apache.logging.log4j:log4j-slf4j2-impl:2.24.3
│
├── com.google.guava:guava:29.0-jre
├── commons-fileupload:commons-fileupload:1.6.0
├── commons-io:commons-io:2.7
├── commons-codec:commons-codec:1.18.0
├── org.apache.commons:commons-lang3:3.4
├── org.apache.commons:commons-text:1.4
│
├── org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.9
├── org.webjars:swagger-ui:5.21.0
├── com.jayway.jsonpath:json-path:2.7.0
├── org.jsoup:jsoup:1.15.3
├── com.google.code.gson:gson:2.13.1
│
└── jakarta.annotation:jakarta.annotation-api:1.3.5
"""


# =============================================================================
# SAMPLE JFROG VULNERABILITIES - What you would get from JFrog scan
# =============================================================================

SAMPLE_VULNERABILITIES = [
    # Example 1: Tomcat vulnerability
    JFrogVulnerability(
        vulnerable_ga="org.apache.tomcat.embed:tomcat-embed-core",
        vulnerable_version="10.1.42",
        fixed_versions=["10.1.45", "10.1.44", "10.1.43"],  # From JFrog
        cve_id="CVE-2024-XXXX",
        severity="HIGH",
        description="Remote code execution vulnerability in Tomcat embedded server"
    ),
    
    # Example 2: Jackson vulnerability
    JFrogVulnerability(
        vulnerable_ga="com.fasterxml.jackson.core:jackson-databind",
        vulnerable_version="2.19.1",
        fixed_versions=["2.19.5", "2.19.4", "2.19.3", "2.19.2"],
        cve_id="CVE-2024-YYYY",
        severity="CRITICAL",
        description="Deserialization vulnerability allowing arbitrary code execution"
    ),
    
    # Example 3: Log4j vulnerability
    JFrogVulnerability(
        vulnerable_ga="org.apache.logging.log4j:log4j-core",
        vulnerable_version="2.24.3",
        fixed_versions=["2.24.5", "2.24.4"],
        cve_id="CVE-2024-ZZZZ",
        severity="MEDIUM",
        description="Denial of service vulnerability in Log4j"
    ),
]


# =============================================================================
# MAIN WORKFLOW
# =============================================================================

def load_dependency_tree(file_path: str = None) -> str:
    """
    Load dependency tree from file or use sample.
    
    In production, you would get this from:
    - mvn dependency:tree
    - gradle dependencies
    - A build system plugin
    """
    if file_path and os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return f.read()
    return SAMPLE_DEPENDENCY_TREE


def load_jfrog_vulnerabilities(file_path: str = None) -> List[JFrogVulnerability]:
    """
    Load vulnerabilities from JFrog scan JSON or use samples.
    
    JFrog scan output typically looks like:
    {
        "vulnerabilities": [
            {
                "component": "org.apache.tomcat.embed:tomcat-embed-core:10.1.42",
                "cve": "CVE-2024-XXXX",
                "severity": "HIGH",
                "fixed_versions": ["10.1.43", "10.1.44", "10.1.45"]
            }
        ]
    }
    """
    if file_path and os.path.exists(file_path):
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        vulnerabilities = []
        for vuln in data.get("vulnerabilities", []):
            # Parse component string (group:artifact:version)
            parts = vuln.get("component", "").split(":")
            if len(parts) >= 3:
                ga = f"{parts[0]}:{parts[1]}"
                version = parts[2]
            else:
                continue
            
            vulnerabilities.append(JFrogVulnerability(
                vulnerable_ga=ga,
                vulnerable_version=version,
                fixed_versions=vuln.get("fixed_versions", []),
                cve_id=vuln.get("cve"),
                severity=vuln.get("severity", "UNKNOWN"),
                description=vuln.get("description", "")
            ))
        
        return vulnerabilities
    
    return SAMPLE_VULNERABILITIES


def print_dependency_graph_summary(graph: DependencyGraph):
    """
    Print a nice summary of the dependency graph.
    """
    print("\n" + "=" * 70)
    print("DEPENDENCY GRAPH SUMMARY")
    print("=" * 70)
    
    summary = graph.get_llm_summary()
    
    print(f"\nProject: {summary['project']}")
    print(f"Total Dependencies: {summary['total_dependencies']}")
    print(f"  - Direct: {summary['direct_count']}")
    print(f"  - Transitive: {summary['transitive_count']}")
    print(f"Max Depth: {summary['max_depth']}")
    
    print("\nHigh-Risk Dependencies (impact > 0.5):")
    for dep in summary['high_risk_dependencies'][:5]:
        print(f"  ⚠️  {dep['ga']} (impact={dep['impact_score']:.2f})")


def print_recommendation(vuln: JFrogVulnerability, rec: VersionRecommendation):
    """
    Print a formatted recommendation.
    """
    print("\n" + "-" * 70)
    print(f"VULNERABILITY: {vuln.vulnerable_ga}")
    print("-" * 70)
    
    print(f"Current Version:     {vuln.vulnerable_version}")
    print(f"Severity:            {vuln.severity}")
    print(f"CVE:                 {vuln.cve_id or 'N/A'}")
    print(f"Available Fixes:     {vuln.fixed_versions}")
    
    print(f"\n{'='*40}")
    print("RECOMMENDATION")
    print(f"{'='*40}")
    print(f"Upgrade to:          {rec.recommended_version}")
    print(f"Risk Level:          {rec.risk_level}")
    print(f"Fallback Versions:   {rec.fallback_versions}")
    
    print(f"\nReasoning:")
    for line in rec.reasoning.split('\n'):
        print(f"  {line}")
    
    if rec.breaking_changes:
        print(f"\n⚠️  Breaking Changes:")
        for change in rec.breaking_changes:
            print(f"    - {change}")
    
    if rec.testing_recommendations:
        print(f"\n🧪 Testing Recommendations:")
        for test in rec.testing_recommendations:
            print(f"    - {test}")


def print_upgrade_strategy(vuln: JFrogVulnerability, strategy: StrategyRecommendation):
    """
    Print the upgrade strategy (HOW to upgrade, not just WHAT version).
    """
    print(f"\n{'='*40}")
    print("UPGRADE STRATEGY")
    print(f"{'='*40}")
    
    # Strategy type with emoji
    strategy_emoji = {
        UpgradeStrategy.DIRECT_UPGRADE: "✅",
        UpgradeStrategy.PARENT_UPGRADE: "⬆️",
        UpgradeStrategy.BOM_OVERRIDE: "📦",
        UpgradeStrategy.FORCE_OVERRIDE: "⚠️",
        UpgradeStrategy.CANNOT_UPGRADE: "🚨",
    }
    
    emoji = strategy_emoji.get(strategy.strategy, "")
    print(f"\nStrategy: {emoji} {strategy.strategy.value.upper()}")
    print(f"Risk Level: {strategy.risk_level}")
    
    if strategy.parent_to_upgrade:
        print(f"\n📌 KEY INSIGHT: This is a TRANSITIVE dependency!")
        print(f"   Brought in by: {strategy.parent_to_upgrade}")
        print(f"   Parent version: {strategy.parent_current_version}")
        if strategy.parent_target_version:
            print(f"   Upgrade parent to: {strategy.parent_target_version}")
    
    print(f"\n📋 STEPS TO UPGRADE:")
    for step in strategy.steps:
        print(f"   {step}")
    
    if strategy.warnings:
        print(f"\n⚠️  WARNINGS:")
        for warning in strategy.warnings:
            if warning:  # Skip empty warnings
                print(f"   {warning}")
    
    print(f"\n🧪 TESTING FOCUS:")
    for test in strategy.testing_focus:
        print(f"   - {test}")


async def main():
    """
    Main entry point.
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="FalconFix v3 - Intelligent Dependency Version Analyzer"
    )
    parser.add_argument(
        "--tree-file",
        help="Path to dependency tree file (default: use sample)"
    )
    parser.add_argument(
        "--jfrog-scan",
        help="Path to JFrog scan JSON file (default: use sample)"
    )
    parser.add_argument(
        "--output",
        help="Path to save results as JSON"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed output"
    )
    args = parser.parse_args()
    
    print("\n" + "=" * 70)
    print("  FALCONFIX v3 - Intelligent Dependency Version Analyzer")
    print("=" * 70)
    
    # Step 1: Load and parse dependency tree
    print("\n📦 Loading dependency tree...")
    tree_text = load_dependency_tree(args.tree_file)
    graph = parse_dependency_tree(tree_text)
    
    if args.verbose:
        print_dependency_graph_summary(graph)
    else:
        print(f"   Parsed {len(graph.nodes)} dependencies")
    
    # Step 2: Load vulnerabilities
    print("\n🔍 Loading vulnerabilities...")
    vulnerabilities = load_jfrog_vulnerabilities(args.jfrog_scan)
    print(f"   Found {len(vulnerabilities)} vulnerabilities to analyze")
    
    for vuln in vulnerabilities:
        print(f"   - {vuln.vulnerable_ga}:{vuln.vulnerable_version} ({vuln.severity})")
    
    # Step 3: Analyze each vulnerability
    print("\n🤖 Analyzing vulnerabilities with AI...")
    print("   (This may take a moment as we fetch changelogs and consult the LLM)")
    
    results: Dict[str, VersionRecommendation] = {}
    analyzer = VersionAnalyzer(graph)
    
    for vuln in vulnerabilities:
        print(f"\n   Analyzing: {vuln.vulnerable_ga}...")
        try:
            recommendation = await analyzer.analyze_vulnerability(vuln)
            results[vuln.vulnerable_ga] = recommendation
            print(f"   ✓ Recommended: {recommendation.recommended_version}")
        except Exception as e:
            print(f"   ✗ Error: {e}")
            results[vuln.vulnerable_ga] = VersionRecommendation(
                recommended_version=vuln.fixed_versions[0] if vuln.fixed_versions else "UNKNOWN",
                reasoning=f"Analysis failed: {e}",
                risk_level="HIGH",
                breaking_changes=["Manual review required"],
                testing_recommendations=["Full regression test required"],
                fallback_versions=vuln.fixed_versions[1:3] if len(vuln.fixed_versions) > 1 else []
            )
    
    # Step 4: Analyze upgrade strategies
    print("\n📊 Determining upgrade strategies...")
    strategy_analyzer = UpgradeStrategyAnalyzer(graph)
    strategies: Dict[str, StrategyRecommendation] = {}
    
    for vuln in vulnerabilities:
        rec = results.get(vuln.vulnerable_ga)
        if rec:
            strategy = strategy_analyzer.get_upgrade_strategy(
                vuln.vulnerable_ga,
                vuln.vulnerable_version,
                rec.recommended_version
            )
            strategies[vuln.vulnerable_ga] = strategy
    
    # Step 5: Print results
    print("\n" + "=" * 70)
    print("ANALYSIS RESULTS")
    print("=" * 70)
    
    for vuln in vulnerabilities:
        rec = results.get(vuln.vulnerable_ga)
        strategy = strategies.get(vuln.vulnerable_ga)
        if rec:
            print_recommendation(vuln, rec)
        if strategy:
            print_upgrade_strategy(vuln, strategy)
    
    # Step 5: Save results if requested
    if args.output:
        output_data = {
            "project": graph.root_project,
            "analysis_results": {
                ga: rec.to_dict() for ga, rec in results.items()
            }
        }
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\n💾 Results saved to: {args.output}")
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total vulnerabilities analyzed: {len(vulnerabilities)}")
    print("\nRecommended upgrades:")
    for vuln in vulnerabilities:
        rec = results.get(vuln.vulnerable_ga)
        if rec:
            print(f"  {vuln.vulnerable_ga}:")
            print(f"    {vuln.vulnerable_version} → {rec.recommended_version} ({rec.risk_level} risk)")
    
    print("\n✅ Analysis complete!")


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    asyncio.run(main())

