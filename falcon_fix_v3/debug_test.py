"""
debug_test.py
=============
A SIMPLE test file for debugging step by step.

HOW TO DEBUG:
1. Open this file in Cursor/VS Code
2. Click on line numbers to add RED breakpoints
3. Press F5 (or Run → Start Debugging)
4. Use these controls:
   - F10: Step Over (next line)
   - F11: Step Into (go inside function)
   - Shift+F11: Step Out (exit function)
   - F5: Continue (run until next breakpoint)

RECOMMENDED BREAKPOINTS:
- Line 40: After parsing dependency tree
- Line 50: After getting dependency info
- Line 60: After determining upgrade strategy
"""

import asyncio
from dependency_graph import parse_dependency_tree, DependencyGraph
from upgrade_strategy import (
    UpgradeStrategyAnalyzer, 
    UpgradeStrategy,
    analyze_upgrade
)

# Simple dependency tree for testing
TEST_TREE = """
com.random-x:part-finder-service-api:1.2.39-SNAPSHOT
├── org.springframework.boot:spring-boot-starter-tomcat:3.5.3
│   └── org.apache.tomcat.embed:tomcat-embed-core:10.1.42
├── com.fasterxml.jackson.core:jackson-databind:2.19.1
└── org.apache.logging.log4j:log4j-core:2.24.3
"""


def main():
    """
    Simple synchronous test - easy to debug!
    """
    print("=" * 60)
    print("DEBUG TEST - Step through with breakpoints")
    print("=" * 60)
    
    # =========================================================
    # STEP 1: Parse the dependency tree
    # =========================================================
    print("\n[STEP 1] Parsing dependency tree...")
    
    graph = parse_dependency_tree(TEST_TREE)  # ← BREAKPOINT HERE
    
    # Inspect these variables in the debugger:
    # - graph.nodes (all dependencies)
    # - graph.root_project (the root project name)
    print(f"   Parsed {len(graph.nodes)} dependencies")
    print(f"   Root project: {graph.root_project}")
    
    # =========================================================
    # STEP 2: Get info about a specific dependency
    # =========================================================
    print("\n[STEP 2] Getting dependency info...")
    
    tomcat_ga = "org.apache.tomcat.embed:tomcat-embed-core"
    tomcat_info = graph.get_dependency_info(tomcat_ga)  # ← BREAKPOINT HERE
    
    # Inspect tomcat_info in the debugger:
    # - tomcat_info["is_direct"] (should be False - it's transitive!)
    # - tomcat_info["parents"] (who brings it in)
    # - tomcat_info["depth"] (how deep in the tree)
    print(f"   GA: {tomcat_info['ga']}")
    print(f"   Version: {tomcat_info['version']}")
    print(f"   Is Direct: {tomcat_info['is_direct']}")
    print(f"   Parents: {tomcat_info['parents']}")
    print(f"   Depth: {tomcat_info['depth']}")
    print(f"   Impact Score: {tomcat_info['impact_score']}")
    
    # =========================================================
    # STEP 3: Determine upgrade strategy
    # =========================================================
    print("\n[STEP 3] Determining upgrade strategy...")
    
    strategy = analyze_upgrade(  # ← BREAKPOINT HERE
        graph=graph,
        vulnerable_ga="org.apache.tomcat.embed:tomcat-embed-core",
        vulnerable_version="10.1.42",
        target_version="10.1.45"
    )
    
    # Inspect strategy in the debugger:
    # - strategy.strategy (should be BOM_OVERRIDE)
    # - strategy.steps (list of steps to take)
    # - strategy.warnings (important warnings)
    print(f"   Strategy: {strategy.strategy.value}")
    print(f"   Risk Level: {strategy.risk_level}")
    
    print("\n[STEP 3a] Steps to upgrade:")
    for step in strategy.steps:
        print(f"   {step}")
    
    print("\n[STEP 3b] Warnings:")
    for warning in strategy.warnings:
        if warning:
            print(f"   {warning}")
    
    # =========================================================
    # STEP 4: Test with a DIRECT dependency
    # =========================================================
    print("\n[STEP 4] Testing with direct dependency...")
    
    jackson_strategy = analyze_upgrade(  # ← BREAKPOINT HERE
        graph=graph,
        vulnerable_ga="com.fasterxml.jackson.core:jackson-databind",
        vulnerable_version="2.19.1",
        target_version="2.19.5"
    )
    
    # This should be DIRECT_UPGRADE (not BOM_OVERRIDE)
    # Because jackson-databind is a direct dependency in our test tree
    print(f"   Strategy: {jackson_strategy.strategy.value}")
    print(f"   (Expected: direct_upgrade because it's a direct dependency)")
    
    # =========================================================
    # DONE
    # =========================================================
    print("\n" + "=" * 60)
    print("DEBUG TEST COMPLETE")
    print("=" * 60)
    print("\nTry adding more breakpoints and stepping through!")
    print("Use F10 (Step Over) and F11 (Step Into) to navigate.")


if __name__ == "__main__":
    main()

