"""
dependency_graph.py
====================
Converts a dependency tree into a graph structure optimized for LLM analysis.

KEY CONCEPTS:
-------------
1. DEPENDENCY TREE: Hierarchical view (parent → children)
   - Good for: Understanding what depends on what
   - Example: Spring Boot → Tomcat → Servlet API

2. DEPENDENCY GRAPH: Flat structure with rich metadata
   - Good for: LLM analysis, risk assessment
   - Contains: depth, centrality, impact score, relationships

WHY CONVERT?
------------
LLMs work better with flat, structured data than deeply nested trees.
The graph format includes pre-computed metrics that help the LLM
understand the IMPACT of changing a particular dependency.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
import json
import re


@dataclass
class DependencyNode:
    """
    Represents a single dependency in the graph.
    
    Attributes:
        ga: Group:Artifact identifier (e.g., "org.springframework:spring-core")
        version: Current version (e.g., "6.2.8")
        depth: How many levels from root (0 = direct dependency)
        is_direct: True if directly declared in pom.xml/build.gradle
        parents: List of GAs that depend on this
        children: List of GAs this depends on
        centrality_score: How "central" this is (0.0 to 1.0)
                          Higher = more things depend on it = riskier to change
        impact_score: Estimated impact of changing this version
                      Combines centrality + depth + number of dependents
    """
    ga: str
    version: str
    depth: int = 0
    is_direct: bool = False
    parents: List[str] = field(default_factory=list)
    children: List[str] = field(default_factory=list)
    centrality_score: float = 0.0
    impact_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "ga": self.ga,
            "version": self.version,
            "depth": self.depth,
            "is_direct": self.is_direct,
            "parents": self.parents,
            "children": self.children,
            "centrality_score": round(self.centrality_score, 3),
            "impact_score": round(self.impact_score, 3),
        }


class DependencyGraph:
    """
    Main class for building and querying the dependency graph.
    
    USAGE:
    ------
    # 1. Parse the tree text
    graph = DependencyGraph()
    graph.parse_tree_text(tree_string)
    
    # 2. Get summary for LLM
    summary = graph.get_llm_summary()
    
    # 3. Query specific dependency
    info = graph.get_dependency_info("org.apache.tomcat.embed:tomcat-embed-core")
    """
    
    def __init__(self):
        # Main storage: GA → DependencyNode
        self.nodes: Dict[str, DependencyNode] = {}
        # Root project info
        self.root_project: Optional[str] = None
        
    def parse_tree_text(self, tree_text: str) -> "DependencyGraph":
        """
        Parse the dependency tree text format into a graph.
        
        INPUT FORMAT:
        -------------
        com.random-x:part-finder-service-api:1.2.39-SNAPSHOT
        ├── org.springframework.boot:spring-boot-starter-tomcat:3.5.3
        │   ├── org.apache.tomcat.embed:tomcat-embed-core:10.1.42
        │   │   ├── jakarta.servlet:jakarta.servlet-api:6.0.0
        
        PARSING STRATEGY:
        -----------------
        1. Count leading tree characters (├, │, └, spaces) to determine depth
        2. Extract GA:version from each line
        3. Track parent at each depth level
        4. Build relationships as we go
        """
        lines = tree_text.strip().split('\n')
        
        # Track parent at each depth level
        # depth_parents[0] = root, depth_parents[1] = first level parent, etc.
        depth_parents: Dict[int, str] = {}
        
        for line in lines:
            if not line.strip():
                continue
                
            # Calculate depth by counting tree characters
            depth = self._calculate_depth(line)
            
            # Extract GA and version
            ga, version = self._extract_ga_version(line)
            if not ga:
                continue
            
            # First line (depth 0) is the root project
            if depth == 0:
                self.root_project = ga
                depth_parents[0] = ga
                self._add_node(ga, version, depth=0, is_direct=True, parent=None)
                continue
            
            # Find parent (one level up)
            parent_ga = depth_parents.get(depth - 1)
            
            # Add or update node
            self._add_node(ga, version, depth=depth, 
                          is_direct=(depth == 1), 
                          parent=parent_ga)
            
            # Update parent tracking for this depth
            depth_parents[depth] = ga
            
            # Clear deeper levels (they're no longer valid parents)
            for d in list(depth_parents.keys()):
                if d > depth:
                    del depth_parents[d]
        
        # Calculate centrality and impact scores
        self._calculate_scores()
        
        return self
    
    def _calculate_depth(self, line: str) -> int:
        """
        Calculate depth from tree characters.
        
        LOGIC:
        ------
        - Each "│" represents a parent level above
        - Each "├" or "└" represents the current branch level
        - Depth = count of "│" + (1 if "├" or "└" exists)
        
        EXAMPLES:
        ---------
        "com.random-x:app:1.0"           → depth 0 (no tree chars)
        "├── spring-boot:3.5.3"         → depth 1 (one ├)
        "│   ├── tomcat:10.1.42"        → depth 2 (one │ + one ├)
        "│   │   ├── servlet-api:6.0"   → depth 3 (two │ + one ├)
        "│   │   └── websocket:10.1.42" → depth 3 (two │ + one └)
        """
        # Remove the actual content to count only tree prefix
        tree_chars = re.match(r'^[│├└─\s]*', line)
        if not tree_chars:
            return 0
        
        prefix = tree_chars.group(0)
        
        # Count │ (vertical bars) = parent levels
        vertical_bars = prefix.count('│')
        
        # Count if there's a branch character (├ or └) = current level
        has_branch = 1 if ('├' in prefix or '└' in prefix) else 0
        
        # Total depth = parent levels + current level
        depth = vertical_bars + has_branch
        
        return depth
    
    def _extract_ga_version(self, line: str) -> tuple:
        """
        Extract group:artifact and version from a line.
        
        EXAMPLES:
        ---------
        "├── org.springframework.boot:spring-boot-starter-tomcat:3.5.3"
        → ("org.springframework.boot:spring-boot-starter-tomcat", "3.5.3")
        
        "com.random-x:part-finder-service-api:1.2.39-SNAPSHOT"
        → ("com.random-x:part-finder-service-api", "1.2.39-SNAPSHOT")
        """
        # Remove tree characters and extra info like "(conflict resolved)"
        clean = re.sub(r'^[│├└─\s]+', '', line)
        clean = re.sub(r'\s*\([^)]*\)\s*', '', clean)  # Remove parenthetical notes
        clean = clean.strip()
        
        if not clean:
            return None, None
        
        # Split on colons: group:artifact:version or group:artifact:packaging:version
        parts = clean.split(':')
        
        if len(parts) >= 3:
            # Standard format: group:artifact:version
            group = parts[0]
            artifact = parts[1]
            version = parts[-1]  # Last part is version (handles packaging:classifier)
            ga = f"{group}:{artifact}"
            return ga, version
        
        return None, None
    
    def _add_node(self, ga: str, version: str, depth: int, 
                  is_direct: bool, parent: Optional[str]):
        """
        Add or update a node in the graph.
        
        IMPORTANT:
        ----------
        Same GA can appear multiple times in the tree (at different depths).
        We keep the FIRST occurrence (shallowest depth) as the canonical one.
        But we track ALL parent relationships.
        """
        if ga not in self.nodes:
            self.nodes[ga] = DependencyNode(
                ga=ga,
                version=version,
                depth=depth,
                is_direct=is_direct,
                parents=[],
                children=[],
            )
        
        node = self.nodes[ga]
        
        # Add parent relationship if not already tracked
        if parent and parent not in node.parents:
            node.parents.append(parent)
            
            # Also update parent's children list
            if parent in self.nodes:
                if ga not in self.nodes[parent].children:
                    self.nodes[parent].children.append(ga)
    
    def _calculate_scores(self):
        """
        Calculate centrality and impact scores for all nodes.
        
        CENTRALITY SCORE (0.0 to 1.0):
        ------------------------------
        Higher = More things depend on this = Riskier to change
        
        Formula: (num_parents + num_children) / max_degree
        - More connections = higher centrality
        - Direct dependencies get a small boost
        
        IMPACT SCORE (0.0 to 1.0):
        --------------------------
        Estimates the "blast radius" of changing this dependency.
        
        Formula: centrality * (1 - depth_penalty) * direct_boost
        - Central deps have higher impact
        - Shallow deps have higher impact (closer to root)
        - Direct deps have higher impact
        """
        if not self.nodes:
            return
        
        # Find max degree for normalization
        max_degree = max(
            len(n.parents) + len(n.children) 
            for n in self.nodes.values()
        )
        max_degree = max(max_degree, 1)  # Avoid division by zero
        
        # Find max depth for normalization
        max_depth = max(n.depth for n in self.nodes.values())
        max_depth = max(max_depth, 1)
        
        for node in self.nodes.values():
            # Centrality: normalized degree
            degree = len(node.parents) + len(node.children)
            node.centrality_score = degree / max_degree
            
            # Impact score
            depth_penalty = node.depth / (max_depth + 1)  # 0 to ~1
            direct_boost = 1.2 if node.is_direct else 1.0
            
            node.impact_score = (
                node.centrality_score * 
                (1 - depth_penalty * 0.5) *  # Depth has 50% weight
                direct_boost
            )
            
            # Clamp to [0, 1]
            node.impact_score = min(1.0, max(0.0, node.impact_score))
    
    def get_dependency_info(self, ga: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed info about a specific dependency.
        
        RETURNS:
        --------
        {
            "ga": "org.apache.tomcat.embed:tomcat-embed-core",
            "version": "10.1.42",
            "depth": 2,
            "is_direct": false,
            "parents": ["org.springframework.boot:spring-boot-starter-tomcat"],
            "children": ["jakarta.servlet:jakarta.servlet-api", ...],
            "centrality_score": 0.45,
            "impact_score": 0.52,
            "risk_assessment": "MEDIUM - Transitive dependency with moderate centrality"
        }
        """
        if ga not in self.nodes:
            return None
        
        node = self.nodes[ga]
        info = node.to_dict()
        
        # Add human-readable risk assessment
        if node.impact_score > 0.7:
            risk = "HIGH - Critical dependency, changes may have wide impact"
        elif node.impact_score > 0.4:
            risk = "MEDIUM - Moderate impact, test thoroughly after changes"
        else:
            risk = "LOW - Isolated dependency, changes likely contained"
        
        info["risk_assessment"] = risk
        
        return info
    
    def get_llm_summary(self) -> Dict[str, Any]:
        """
        Get a summary optimized for LLM consumption.
        
        This is what you pass to the LLM agent.
        Includes:
        - Project overview
        - All dependencies with metadata
        - High-risk dependencies highlighted
        - Statistics
        """
        if not self.nodes:
            return {"error": "No dependencies parsed"}
        
        # Separate direct and transitive
        direct_deps = {ga: n.to_dict() for ga, n in self.nodes.items() if n.is_direct}
        transitive_deps = {ga: n.to_dict() for ga, n in self.nodes.items() if not n.is_direct}
        
        # Find high-risk dependencies (impact > 0.5)
        high_risk = [
            {"ga": ga, "impact_score": n.impact_score, "version": n.version}
            for ga, n in self.nodes.items()
            if n.impact_score > 0.5
        ]
        high_risk.sort(key=lambda x: x["impact_score"], reverse=True)
        
        return {
            "project": self.root_project,
            "total_dependencies": len(self.nodes),
            "direct_count": len(direct_deps),
            "transitive_count": len(transitive_deps),
            "max_depth": max(n.depth for n in self.nodes.values()),
            "high_risk_dependencies": high_risk[:10],  # Top 10
            "direct_dependencies": direct_deps,
            "transitive_dependencies": transitive_deps,
            "all_dependencies": {ga: n.to_dict() for ga, n in self.nodes.items()},
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Export graph as JSON string."""
        return json.dumps(self.get_llm_summary(), indent=indent)
    
    def pretty_print(self) -> str:
        """
        Pretty print the graph for debugging.
        """
        lines = [f"Dependency Graph for: {self.root_project}"]
        lines.append(f"Total: {len(self.nodes)} dependencies")
        lines.append("-" * 60)
        
        # Sort by depth, then by GA
        sorted_nodes = sorted(
            self.nodes.values(), 
            key=lambda n: (n.depth, n.ga)
        )
        
        for node in sorted_nodes:
            indent = "  " * node.depth
            direct_mark = "[D]" if node.is_direct else "[T]"
            risk_mark = "⚠️" if node.impact_score > 0.5 else ""
            lines.append(
                f"{indent}{direct_mark} {node.ga}:{node.version} "
                f"(impact={node.impact_score:.2f}) {risk_mark}"
            )
        
        return "\n".join(lines)


# =============================================================================
# CONVENIENCE FUNCTION
# =============================================================================

def parse_dependency_tree(tree_text: str) -> DependencyGraph:
    """
    One-liner to parse a dependency tree.
    
    EXAMPLE:
    --------
    tree_text = '''
    com.random-x:my-app:1.0.0
    ├── org.springframework:spring-core:6.2.8
    │   └── org.springframework:spring-jcl:6.2.8
    '''
    
    graph = parse_dependency_tree(tree_text)
    print(graph.pretty_print())
    """
    graph = DependencyGraph()
    graph.parse_tree_text(tree_text)
    return graph


# =============================================================================
# TESTING
# =============================================================================

if __name__ == "__main__":
    # Test with the provided dependency tree
    test_tree = """
com.random-x:part-finder-service-api:1.2.39-SNAPSHOT
├── org.springframework.boot:spring-boot-starter-tomcat:3.5.3
│   ├── org.apache.tomcat.embed:tomcat-embed-core:10.1.42
│   │   ├── jakarta.servlet:jakarta.servlet-api:6.0.0
│   │   ├── org.apache.tomcat.embed:tomcat-embed-el:10.1.42
│   │   └── org.apache.tomcat.embed:tomcat-embed-websocket:10.1.42
├── org.springframework.boot:spring-boot-starter-web:3.5.3
│   ├── org.springframework.boot:spring-boot-starter:3.5.3
│   │   ├── org.springframework.boot:spring-boot:3.5.3
│   │   │   └── org.springframework:spring-core:6.2.8
"""
    
    graph = parse_dependency_tree(test_tree)
    print(graph.pretty_print())
    print("\n" + "=" * 60 + "\n")
    
    # Get info for a specific dependency
    info = graph.get_dependency_info("org.apache.tomcat.embed:tomcat-embed-core")
    if info:
        print("Tomcat Core Info:")
        print(json.dumps(info, indent=2))

