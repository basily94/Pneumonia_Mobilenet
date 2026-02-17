"""
upgrade_strategy.py
===================
Determines the CORRECT upgrade strategy based on dependency type.

KEY INSIGHT:
------------
You CANNOT just upgrade a transitive dependency directly.
You must consider the PARENT that brings it in.

UPGRADE STRATEGIES:
-------------------
1. DIRECT_UPGRADE: Dependency is direct, upgrade it
2. PARENT_UPGRADE: Upgrade the parent to get the fixed transitive
3. BOM_OVERRIDE: Use Spring Boot BOM property to override safely
4. FORCE_OVERRIDE: Force version (risky, needs testing)
5. CANNOT_UPGRADE: No safe path, manual intervention needed
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import re

from dependency_graph import DependencyGraph, DependencyNode


class UpgradeStrategy(Enum):
    """
    The recommended way to upgrade a dependency.
    """
    DIRECT_UPGRADE = "direct_upgrade"      # It's a direct dep, just upgrade
    PARENT_UPGRADE = "parent_upgrade"      # Upgrade the parent instead
    BOM_OVERRIDE = "bom_override"          # Use Spring Boot BOM property
    FORCE_OVERRIDE = "force_override"      # Force version (risky)
    CANNOT_UPGRADE = "cannot_upgrade"      # No safe path


@dataclass
class UpgradeRecommendation:
    """
    Complete upgrade recommendation with strategy and steps.
    """
    vulnerable_ga: str
    vulnerable_version: str
    target_version: str
    
    # The strategy to use
    strategy: UpgradeStrategy
    
    # What to actually upgrade (might be different from vulnerable_ga)
    upgrade_target_ga: str
    upgrade_target_version: str
    
    # Risk assessment
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Step-by-step instructions
    steps: List[str] = field(default_factory=list)
    
    # Warnings
    warnings: List[str] = field(default_factory=list)
    
    # What to test
    testing_focus: List[str] = field(default_factory=list)
    
    # If strategy is PARENT_UPGRADE, which parent?
    parent_to_upgrade: Optional[str] = None
    parent_current_version: Optional[str] = None
    parent_target_version: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerable_ga": self.vulnerable_ga,
            "vulnerable_version": self.vulnerable_version,
            "target_version": self.target_version,
            "strategy": self.strategy.value,
            "upgrade_target_ga": self.upgrade_target_ga,
            "upgrade_target_version": self.upgrade_target_version,
            "risk_level": self.risk_level,
            "steps": self.steps,
            "warnings": self.warnings,
            "testing_focus": self.testing_focus,
            "parent_to_upgrade": self.parent_to_upgrade,
            "parent_current_version": self.parent_current_version,
            "parent_target_version": self.parent_target_version,
        }


# =============================================================================
# SPRING BOOT BOM PROPERTIES
# =============================================================================
# These are properties you can set in pom.xml to override versions safely
# Spring Boot manages these dependencies and ensures compatibility

SPRING_BOOT_BOM_PROPERTIES = {
    # Tomcat
    "org.apache.tomcat.embed:tomcat-embed-core": "tomcat.version",
    "org.apache.tomcat.embed:tomcat-embed-el": "tomcat.version",
    "org.apache.tomcat.embed:tomcat-embed-websocket": "tomcat.version",
    
    # Jackson
    "com.fasterxml.jackson.core:jackson-databind": "jackson-bom.version",
    "com.fasterxml.jackson.core:jackson-core": "jackson-bom.version",
    "com.fasterxml.jackson.core:jackson-annotations": "jackson-bom.version",
    
    # Log4j
    "org.apache.logging.log4j:log4j-core": "log4j2.version",
    "org.apache.logging.log4j:log4j-api": "log4j2.version",
    
    # Netty
    "io.netty:netty-handler": "netty.version",
    "io.netty:netty-buffer": "netty.version",
    "io.netty:netty-transport": "netty.version",
    
    # Hibernate
    "org.hibernate.orm:hibernate-core": "hibernate.version",
    
    # Spring Framework
    "org.springframework:spring-core": "spring-framework.version",
    "org.springframework:spring-context": "spring-framework.version",
    "org.springframework:spring-web": "spring-framework.version",
    
    # Logback
    "ch.qos.logback:logback-classic": "logback.version",
    "ch.qos.logback:logback-core": "logback.version",
}


# =============================================================================
# VERSION UTILITIES
# =============================================================================

def parse_version(version: str) -> Tuple[int, int, int, str]:
    """
    Parse version string into (major, minor, patch, qualifier).
    
    Examples:
        "10.1.42" → (10, 1, 42, "")
        "3.5.3" → (3, 5, 3, "")
        "2.19.1-SNAPSHOT" → (2, 19, 1, "SNAPSHOT")
    """
    # Remove common qualifiers for parsing
    qualifiers = ["SNAPSHOT", "Final", "RELEASE", "GA"]
    qualifier = ""
    clean_version = version
    
    for q in qualifiers:
        if q in version:
            qualifier = q
            clean_version = version.replace(f"-{q}", "").replace(f".{q}", "")
            break
    
    # Extract numbers
    parts = re.findall(r'\d+', clean_version)
    
    major = int(parts[0]) if len(parts) > 0 else 0
    minor = int(parts[1]) if len(parts) > 1 else 0
    patch = int(parts[2]) if len(parts) > 2 else 0
    
    return (major, minor, patch, qualifier)


def is_same_major_minor(v1: str, v2: str) -> bool:
    """
    Check if two versions have the same major.minor.
    
    Example:
        "10.1.42", "10.1.45" → True (both 10.1.x)
        "10.1.42", "10.2.0" → False (10.1 vs 10.2)
        "2.9.0", "2.15.0" → False (2.9 vs 2.15)
    """
    p1 = parse_version(v1)
    p2 = parse_version(v2)
    return p1[0] == p2[0] and p1[1] == p2[1]


def is_same_major(v1: str, v2: str) -> bool:
    """
    Check if two versions have the same major version.
    """
    p1 = parse_version(v1)
    p2 = parse_version(v2)
    return p1[0] == p2[0]


def version_jump_type(from_v: str, to_v: str) -> str:
    """
    Determine the type of version jump.
    
    Returns: "patch", "minor", "major"
    """
    p1 = parse_version(from_v)
    p2 = parse_version(to_v)
    
    if p1[0] != p2[0]:
        return "major"
    elif p1[1] != p2[1]:
        return "minor"
    else:
        return "patch"


# =============================================================================
# UPGRADE STRATEGY ANALYZER
# =============================================================================

class UpgradeStrategyAnalyzer:
    """
    Analyzes the dependency graph to determine the best upgrade strategy.
    
    USAGE:
    ------
    analyzer = UpgradeStrategyAnalyzer(dependency_graph)
    
    recommendation = analyzer.get_upgrade_strategy(
        vulnerable_ga="org.apache.tomcat.embed:tomcat-embed-core",
        vulnerable_version="10.1.42",
        target_version="10.1.45"
    )
    
    print(recommendation.strategy)  # UpgradeStrategy.BOM_OVERRIDE
    print(recommendation.steps)     # ["Add <tomcat.version>10.1.45</tomcat.version>"]
    """
    
    def __init__(self, graph: DependencyGraph):
        self.graph = graph
    
    def get_upgrade_strategy(
        self,
        vulnerable_ga: str,
        vulnerable_version: str,
        target_version: str,
        available_parent_versions: Dict[str, List[str]] = None
    ) -> UpgradeRecommendation:
        """
        Determine the best upgrade strategy for a vulnerable dependency.
        
        Args:
            vulnerable_ga: The vulnerable group:artifact
            vulnerable_version: Current vulnerable version
            target_version: Target fixed version
            available_parent_versions: Dict of parent GA → available versions
                                       (used to check if parent can be upgraded)
        
        Returns:
            UpgradeRecommendation with strategy and steps
        """
        dep_info = self.graph.get_dependency_info(vulnerable_ga)
        
        if not dep_info:
            # Dependency not in graph - assume direct
            return self._create_direct_upgrade(
                vulnerable_ga, vulnerable_version, target_version
            )
        
        # Check if it's a direct dependency
        if dep_info["is_direct"]:
            return self._create_direct_upgrade(
                vulnerable_ga, vulnerable_version, target_version
            )
        
        # It's a TRANSITIVE dependency - need more analysis
        return self._analyze_transitive_upgrade(
            vulnerable_ga,
            vulnerable_version,
            target_version,
            dep_info,
            available_parent_versions or {}
        )
    
    def _create_direct_upgrade(
        self,
        ga: str,
        from_version: str,
        to_version: str
    ) -> UpgradeRecommendation:
        """
        Create recommendation for a direct dependency upgrade.
        """
        jump_type = version_jump_type(from_version, to_version)
        
        risk = "LOW" if jump_type == "patch" else "MEDIUM" if jump_type == "minor" else "HIGH"
        
        group, artifact = ga.split(":")
        
        return UpgradeRecommendation(
            vulnerable_ga=ga,
            vulnerable_version=from_version,
            target_version=to_version,
            strategy=UpgradeStrategy.DIRECT_UPGRADE,
            upgrade_target_ga=ga,
            upgrade_target_version=to_version,
            risk_level=risk,
            steps=[
                f"1. Open your pom.xml (or build.gradle)",
                f"2. Find the dependency: {ga}",
                f"3. Change version from {from_version} to {to_version}",
                f"4. Run: mvn clean install",
                f"5. Run your test suite",
            ],
            warnings=[
                f"This is a {jump_type} version jump",
                "Review the changelog for breaking changes" if jump_type != "patch" else "",
            ],
            testing_focus=[
                "Unit tests for components using this dependency",
                "Integration tests",
            ]
        )
    
    def _analyze_transitive_upgrade(
        self,
        vulnerable_ga: str,
        vulnerable_version: str,
        target_version: str,
        dep_info: Dict[str, Any],
        available_parent_versions: Dict[str, List[str]]
    ) -> UpgradeRecommendation:
        """
        Analyze and recommend strategy for transitive dependency.
        
        PRIORITY ORDER:
        1. Can parent be upgraded to bring in the fix? → PARENT_UPGRADE
        2. Is there a Spring Boot BOM property? → BOM_OVERRIDE
        3. Is it a safe version jump (patch)? → FORCE_OVERRIDE with caution
        4. Otherwise → CANNOT_UPGRADE (needs manual intervention)
        """
        parents = dep_info.get("parents", [])
        
        if not parents:
            # No parents recorded - treat as direct
            return self._create_direct_upgrade(
                vulnerable_ga, vulnerable_version, target_version
            )
        
        # Get the immediate parent
        immediate_parent = parents[0]
        parent_info = self.graph.get_dependency_info(immediate_parent)
        
        # Strategy 1: Check if parent can be upgraded
        if immediate_parent in available_parent_versions:
            parent_versions = available_parent_versions[immediate_parent]
            # In a real system, you'd check which parent version includes the fix
            # For now, we recommend checking the latest parent
            if parent_versions:
                return self._create_parent_upgrade(
                    vulnerable_ga, vulnerable_version, target_version,
                    immediate_parent,
                    parent_info.get("version") if parent_info else "unknown",
                    parent_versions[0]  # Latest parent version
                )
        
        # Strategy 2: Check for Spring Boot BOM property
        if vulnerable_ga in SPRING_BOOT_BOM_PROPERTIES:
            bom_property = SPRING_BOOT_BOM_PROPERTIES[vulnerable_ga]
            return self._create_bom_override(
                vulnerable_ga, vulnerable_version, target_version,
                bom_property, immediate_parent
            )
        
        # Strategy 3: Check if it's a safe version jump
        if is_same_major_minor(vulnerable_version, target_version):
            return self._create_force_override(
                vulnerable_ga, vulnerable_version, target_version,
                immediate_parent, risk="MEDIUM"
            )
        
        if is_same_major(vulnerable_version, target_version):
            return self._create_force_override(
                vulnerable_ga, vulnerable_version, target_version,
                immediate_parent, risk="HIGH"
            )
        
        # Strategy 4: Major version change - very risky
        return self._create_cannot_upgrade(
            vulnerable_ga, vulnerable_version, target_version,
            immediate_parent
        )
    
    def _create_parent_upgrade(
        self,
        vulnerable_ga: str,
        vulnerable_version: str,
        target_version: str,
        parent_ga: str,
        parent_current: str,
        parent_target: str
    ) -> UpgradeRecommendation:
        """
        Create recommendation to upgrade the parent dependency.
        """
        parent_group, parent_artifact = parent_ga.split(":")
        
        return UpgradeRecommendation(
            vulnerable_ga=vulnerable_ga,
            vulnerable_version=vulnerable_version,
            target_version=target_version,
            strategy=UpgradeStrategy.PARENT_UPGRADE,
            upgrade_target_ga=parent_ga,
            upgrade_target_version=parent_target,
            risk_level="LOW",  # Parent upgrades are usually safer
            parent_to_upgrade=parent_ga,
            parent_current_version=parent_current,
            parent_target_version=parent_target,
            steps=[
                f"1. DO NOT add {vulnerable_ga} directly to your pom.xml",
                f"2. Instead, upgrade the PARENT: {parent_ga}",
                f"3. Change {parent_ga} from {parent_current} to {parent_target}",
                f"4. The fixed {vulnerable_ga} will come automatically",
                f"5. Run: mvn dependency:tree to verify",
                f"6. Run your test suite",
            ],
            warnings=[
                f"⚠️ {vulnerable_ga} is a TRANSITIVE dependency",
                f"⚠️ It's brought in by {parent_ga}",
                f"✅ Upgrading the parent is the SAFEST approach",
            ],
            testing_focus=[
                f"All functionality using {parent_artifact}",
                "Integration tests",
                "End-to-end tests",
            ]
        )
    
    def _create_bom_override(
        self,
        vulnerable_ga: str,
        vulnerable_version: str,
        target_version: str,
        bom_property: str,
        parent_ga: str
    ) -> UpgradeRecommendation:
        """
        Create recommendation to use Spring Boot BOM property override.
        """
        return UpgradeRecommendation(
            vulnerable_ga=vulnerable_ga,
            vulnerable_version=vulnerable_version,
            target_version=target_version,
            strategy=UpgradeStrategy.BOM_OVERRIDE,
            upgrade_target_ga=vulnerable_ga,
            upgrade_target_version=target_version,
            risk_level="LOW" if is_same_major_minor(vulnerable_version, target_version) else "MEDIUM",
            steps=[
                f"1. Open your pom.xml",
                f"2. Add this property to <properties> section:",
                f"   <{bom_property}>{target_version}</{bom_property}>",
                f"3. This will override the version managed by Spring Boot BOM",
                f"4. Run: mvn dependency:tree | grep {vulnerable_ga.split(':')[1]}",
                f"5. Verify it shows version {target_version}",
                f"6. Run your test suite",
            ],
            warnings=[
                f"⚠️ {vulnerable_ga} is managed by Spring Boot BOM",
                f"✅ Using BOM property is the RECOMMENDED way to override",
                f"This ensures all related modules use the same version",
            ],
            testing_focus=[
                "All web/API endpoints",
                "Serialization/deserialization tests",
                "Integration tests",
            ]
        )
    
    def _create_force_override(
        self,
        vulnerable_ga: str,
        vulnerable_version: str,
        target_version: str,
        parent_ga: str,
        risk: str
    ) -> UpgradeRecommendation:
        """
        Create recommendation to force version override (with warnings).
        """
        group, artifact = vulnerable_ga.split(":")
        
        return UpgradeRecommendation(
            vulnerable_ga=vulnerable_ga,
            vulnerable_version=vulnerable_version,
            target_version=target_version,
            strategy=UpgradeStrategy.FORCE_OVERRIDE,
            upgrade_target_ga=vulnerable_ga,
            upgrade_target_version=target_version,
            risk_level=risk,
            steps=[
                f"1. ⚠️ WARNING: This is a forced override of a transitive dependency",
                f"2. Add explicit dependency to pom.xml:",
                f"   <dependency>",
                f"     <groupId>{group}</groupId>",
                f"     <artifactId>{artifact}</artifactId>",
                f"     <version>{target_version}</version>",
                f"   </dependency>",
                f"3. This will override the version from {parent_ga}",
                f"4. Run: mvn dependency:tree to verify",
                f"5. ⚠️ EXTENSIVE TESTING REQUIRED",
            ],
            warnings=[
                f"🚨 This forces a version that {parent_ga} was NOT tested with",
                f"🚨 {parent_ga} expects {vulnerable_version}, you're giving it {target_version}",
                f"🚨 This might cause runtime errors if APIs changed",
                f"Consider upgrading {parent_ga} instead if possible",
            ],
            testing_focus=[
                "⚠️ FULL REGRESSION TEST REQUIRED",
                f"All functionality using {parent_ga}",
                "Runtime error detection (NoSuchMethodError, ClassNotFoundException)",
                "Load testing",
                "End-to-end tests",
            ]
        )
    
    def _create_cannot_upgrade(
        self,
        vulnerable_ga: str,
        vulnerable_version: str,
        target_version: str,
        parent_ga: str
    ) -> UpgradeRecommendation:
        """
        Create recommendation when no safe upgrade path exists.
        """
        return UpgradeRecommendation(
            vulnerable_ga=vulnerable_ga,
            vulnerable_version=vulnerable_version,
            target_version=target_version,
            strategy=UpgradeStrategy.CANNOT_UPGRADE,
            upgrade_target_ga=vulnerable_ga,
            upgrade_target_version=target_version,
            risk_level="CRITICAL",
            steps=[
                f"1. 🚨 NO SAFE AUTOMATIC UPGRADE PATH",
                f"2. This requires MANUAL intervention:",
                f"   a. Check if {parent_ga} has a newer version",
                f"   b. Check if there's an alternative to {parent_ga}",
                f"   c. Consider accepting the vulnerability with mitigations",
                f"3. The version jump {vulnerable_version} → {target_version} is MAJOR",
                f"4. Forcing this version WILL LIKELY BREAK your application",
            ],
            warnings=[
                f"🚨 CRITICAL: Major version change detected",
                f"🚨 {vulnerable_version} → {target_version} crosses major/minor boundaries",
                f"🚨 {parent_ga} almost certainly won't work with {target_version}",
                f"🚨 Manual analysis required",
            ],
            testing_focus=[
                "DO NOT PROCEED without manual analysis",
                "Contact the library maintainers",
                "Consider alternative libraries",
            ]
        )


# =============================================================================
# CONVENIENCE FUNCTION
# =============================================================================

def analyze_upgrade(
    graph: DependencyGraph,
    vulnerable_ga: str,
    vulnerable_version: str,
    target_version: str,
    available_parent_versions: Dict[str, List[str]] = None
) -> UpgradeRecommendation:
    """
    One-liner to analyze an upgrade.
    
    USAGE:
    ------
    recommendation = analyze_upgrade(
        graph,
        "org.apache.tomcat.embed:tomcat-embed-core",
        "10.1.42",
        "10.1.45"
    )
    
    print(recommendation.strategy)  # UpgradeStrategy.BOM_OVERRIDE
    for step in recommendation.steps:
        print(step)
    """
    analyzer = UpgradeStrategyAnalyzer(graph)
    return analyzer.get_upgrade_strategy(
        vulnerable_ga,
        vulnerable_version,
        target_version,
        available_parent_versions
    )


# =============================================================================
# TESTING
# =============================================================================

if __name__ == "__main__":
    from dependency_graph import parse_dependency_tree
    
    # Test tree
    tree = """
com.random-x:part-finder-service-api:1.2.39-SNAPSHOT
├── org.springframework.boot:spring-boot-starter-tomcat:3.5.3
│   └── org.apache.tomcat.embed:tomcat-embed-core:10.1.42
├── com.fasterxml.jackson.core:jackson-databind:2.19.1
"""
    
    graph = parse_dependency_tree(tree)
    
    print("=" * 70)
    print("TEST 1: Transitive dependency with BOM property")
    print("=" * 70)
    
    rec = analyze_upgrade(
        graph,
        "org.apache.tomcat.embed:tomcat-embed-core",
        "10.1.42",
        "10.1.45"
    )
    
    print(f"Strategy: {rec.strategy.value}")
    print(f"Risk: {rec.risk_level}")
    print("\nSteps:")
    for step in rec.steps:
        print(f"  {step}")
    print("\nWarnings:")
    for warning in rec.warnings:
        print(f"  {warning}")
    
    print("\n" + "=" * 70)
    print("TEST 2: Direct dependency")
    print("=" * 70)
    
    rec = analyze_upgrade(
        graph,
        "com.fasterxml.jackson.core:jackson-databind",
        "2.19.1",
        "2.19.5"
    )
    
    print(f"Strategy: {rec.strategy.value}")
    print(f"Risk: {rec.risk_level}")
    print("\nSteps:")
    for step in rec.steps:
        print(f"  {step}")

