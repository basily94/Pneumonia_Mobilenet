"""
changelog_fetcher.py
====================
Fetches changelog data for dependencies.

STRATEGY:
---------
1. PRIMARY: Hit the Spring Boot Release Notes API or GitHub Releases API
2. FALLBACK: Use Playwright browser to scrape changelog pages

WHY TWO METHODS?
----------------
- APIs are fast and reliable, but not all projects have them
- Web scraping works for any project with a changelog page
- Playwright handles JavaScript-rendered pages (GitHub, etc.)

SUPPORTED SOURCES:
------------------
- GitHub Releases (most common)
- Spring Boot Release Notes
- Apache Project Changelogs
- Maven Repository descriptions
"""

import os
import re
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from bs4 import BeautifulSoup

# Optional: Playwright for browser-based scraping
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("Warning: Playwright not installed. Browser fallback disabled.")
    print("Install with: pip install playwright && python -m playwright install chromium")


# =============================================================================
# CONFIGURATION
# =============================================================================

# User agent for HTTP requests (avoid being blocked)
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# GitHub API token (optional, increases rate limits)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Known changelog URLs for common dependencies
# Format: "group:artifact" → URL template (use {version} placeholder)
KNOWN_CHANGELOG_URLS = {
    # Spring Framework
    "org.springframework:spring-core": 
        "https://github.com/spring-projects/spring-framework/releases/tag/v{version}",
    "org.springframework.boot:spring-boot": 
        "https://github.com/spring-projects/spring-boot/releases/tag/v{version}",
    
    # Apache Tomcat
    "org.apache.tomcat.embed:tomcat-embed-core": 
        "https://tomcat.apache.org/tomcat-10.1-doc/changelog.html",
    
    # Jackson
    "com.fasterxml.jackson.core:jackson-databind": 
        "https://github.com/FasterXML/jackson-databind/releases/tag/{version}",
    
    # Netty
    "io.netty:netty-handler": 
        "https://github.com/netty/netty/releases/tag/netty-{version}",
    
    # Hibernate
    "org.hibernate.orm:hibernate-core": 
        "https://github.com/hibernate/hibernate-orm/releases/tag/{version}",
    
    # Log4j
    "org.apache.logging.log4j:log4j-core": 
        "https://github.com/apache/logging-log4j2/releases/tag/rel%2F{version}",
}

# GitHub API mapping: "group:artifact" → "owner/repo"
GITHUB_REPOS = {
    "org.springframework:spring-core": "spring-projects/spring-framework",
    "org.springframework.boot:spring-boot": "spring-projects/spring-boot",
    "com.fasterxml.jackson.core:jackson-databind": "FasterXML/jackson-databind",
    "io.netty:netty-handler": "netty/netty",
    "org.hibernate.orm:hibernate-core": "hibernate/hibernate-orm",
    "org.apache.logging.log4j:log4j-core": "apache/logging-log4j2",
    "com.google.guava:guava": "google/guava",
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ChangelogEntry:
    """
    Represents changelog data for a specific version.
    
    Attributes:
        version: The version this changelog is for
        release_date: When this version was released (if available)
        summary: Brief summary of changes
        breaking_changes: List of breaking changes (IMPORTANT for version selection)
        bug_fixes: List of bug fixes
        new_features: List of new features
        security_fixes: List of security fixes (CRITICAL for vulnerability fixing)
        raw_text: The full changelog text
        source_url: Where this data came from
    """
    version: str
    release_date: Optional[str] = None
    summary: str = ""
    breaking_changes: List[str] = None
    bug_fixes: List[str] = None
    new_features: List[str] = None
    security_fixes: List[str] = None
    raw_text: str = ""
    source_url: str = ""
    
    def __post_init__(self):
        # Initialize lists to empty if None
        self.breaking_changes = self.breaking_changes or []
        self.bug_fixes = self.bug_fixes or []
        self.new_features = self.new_features or []
        self.security_fixes = self.security_fixes or []
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "release_date": self.release_date,
            "summary": self.summary,
            "breaking_changes": self.breaking_changes,
            "bug_fixes": self.bug_fixes,
            "new_features": self.new_features,
            "security_fixes": self.security_fixes,
            "has_breaking_changes": len(self.breaking_changes) > 0,
            "source_url": self.source_url,
        }
    
    def get_risk_summary(self) -> str:
        """
        Generate a risk summary for LLM consumption.
        
        This helps the LLM quickly understand the risk level.
        """
        risks = []
        
        if self.breaking_changes:
            risks.append(f"⚠️ {len(self.breaking_changes)} BREAKING CHANGE(S)")
        if self.security_fixes:
            risks.append(f"🔒 {len(self.security_fixes)} security fix(es)")
        if self.bug_fixes:
            risks.append(f"🐛 {len(self.bug_fixes)} bug fix(es)")
        if self.new_features:
            risks.append(f"✨ {len(self.new_features)} new feature(s)")
        
        if not risks:
            return "No significant changes detected"
        
        return " | ".join(risks)


# =============================================================================
# GITHUB API FETCHER
# =============================================================================

async def fetch_github_release(
    session: aiohttp.ClientSession,
    owner_repo: str,
    version: str
) -> Optional[ChangelogEntry]:
    """
    Fetch changelog from GitHub Releases API.
    
    WHY USE API?
    ------------
    - Fast and structured
    - No HTML parsing needed
    - Returns markdown body with full release notes
    
    RATE LIMITS:
    ------------
    - Without token: 60 requests/hour
    - With token: 5000 requests/hour
    - Set GITHUB_TOKEN env var to avoid limits
    """
    # Try different tag formats
    tag_candidates = [
        f"v{version}",           # v3.5.3
        version,                  # 3.5.3
        f"release-{version}",     # release-3.5.3
        f"rel/{version}",         # rel/3.5.3
    ]
    
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    
    for tag in tag_candidates:
        url = f"https://api.github.com/repos/{owner_repo}/releases/tags/{tag}"
        
        try:
            async with session.get(url, headers=headers, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return _parse_github_release(data, version)
                elif resp.status == 404:
                    continue  # Try next tag format
                else:
                    print(f"GitHub API error: {resp.status} for {url}")
        except Exception as e:
            print(f"Error fetching GitHub release: {e}")
    
    return None


def _parse_github_release(data: Dict[str, Any], version: str) -> ChangelogEntry:
    """
    Parse GitHub release JSON into ChangelogEntry.
    
    GitHub release body is usually markdown with sections like:
    - ## Breaking Changes
    - ## Bug Fixes
    - ## New Features
    - ## Security
    """
    body = data.get("body", "") or ""
    
    # Extract sections from markdown
    breaking = _extract_section(body, ["breaking", "incompatible", "migration"])
    bugs = _extract_section(body, ["bug", "fix", "patch"])
    features = _extract_section(body, ["feature", "enhancement", "improvement"])
    security = _extract_section(body, ["security", "cve", "vulnerability"])
    
    return ChangelogEntry(
        version=version,
        release_date=data.get("published_at", "")[:10] if data.get("published_at") else None,
        summary=data.get("name", f"Release {version}"),
        breaking_changes=breaking,
        bug_fixes=bugs,
        new_features=features,
        security_fixes=security,
        raw_text=body[:5000],  # Limit size
        source_url=data.get("html_url", ""),
    )


def _extract_section(text: str, keywords: List[str]) -> List[str]:
    """
    Extract bullet points from sections matching keywords.
    
    EXAMPLE:
    --------
    Input: "## Bug Fixes\n- Fix NPE in handler\n- Fix timeout issue"
    Keywords: ["bug", "fix"]
    Output: ["Fix NPE in handler", "Fix timeout issue"]
    """
    lines = text.split('\n')
    in_section = False
    items = []
    
    for line in lines:
        line_lower = line.lower()
        
        # Check if this is a section header
        if line.startswith('#'):
            in_section = any(kw in line_lower for kw in keywords)
            continue
        
        # If in relevant section, extract bullet points
        if in_section:
            # Handle different bullet formats: -, *, •
            match = re.match(r'^[\s]*[-*•]\s*(.+)$', line)
            if match:
                items.append(match.group(1).strip())
            elif line.strip() == '':
                continue  # Skip empty lines
            elif line.startswith('#'):
                break  # New section started
    
    return items[:10]  # Limit to 10 items


# =============================================================================
# PLAYWRIGHT BROWSER FETCHER (FALLBACK)
# =============================================================================

async def fetch_changelog_browser(
    url: str,
    version: str
) -> Optional[ChangelogEntry]:
    """
    Fetch changelog by rendering the page with a browser.
    
    WHY BROWSER?
    ------------
    - Some sites use JavaScript to render content
    - GitHub release pages, for example, load content dynamically
    - Browser ensures we get the fully rendered page
    
    WHEN TO USE:
    ------------
    - API failed or not available
    - Page requires JavaScript
    - Need to scroll or interact
    """
    if not PLAYWRIGHT_AVAILABLE:
        print("Playwright not available, skipping browser fetch")
        return None
    
    try:
        async with async_playwright() as p:
            # Launch headless browser
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(user_agent=USER_AGENT)
            page = await context.new_page()
            
            # Set reasonable timeout
            page.set_default_timeout(20000)
            
            # Navigate to the URL
            await page.goto(url, wait_until="domcontentloaded")
            
            # Wait a bit for dynamic content
            await asyncio.sleep(1)
            
            # Get page content
            html = await page.content()
            
            # Close browser
            await browser.close()
            
            # Parse the HTML
            return _parse_changelog_html(html, version, url)
            
    except Exception as e:
        print(f"Browser fetch error: {e}")
        return None


def _parse_changelog_html(html: str, version: str, url: str) -> Optional[ChangelogEntry]:
    """
    Parse changelog from HTML content.
    
    STRATEGY:
    ---------
    1. Look for markdown-body class (GitHub)
    2. Look for release notes section
    3. Extract text content
    4. Parse for breaking changes, fixes, etc.
    """
    soup = BeautifulSoup(html, "html.parser")
    
    # Try different selectors for changelog content
    selectors = [
        ".markdown-body",           # GitHub
        ".release-body",            # GitHub releases
        "#release-notes",           # Spring
        ".changelog",               # Generic
        "article",                  # Generic
        "main",                     # Generic
    ]
    
    content = None
    for selector in selectors:
        element = soup.select_one(selector)
        if element:
            content = element.get_text("\n", strip=True)
            break
    
    if not content:
        # Fallback: get all text from body
        body = soup.find("body")
        if body:
            content = body.get_text("\n", strip=True)
    
    if not content:
        return None
    
    # Extract sections
    breaking = _extract_section(content, ["breaking", "incompatible"])
    bugs = _extract_section(content, ["bug", "fix"])
    features = _extract_section(content, ["feature", "enhancement"])
    security = _extract_section(content, ["security", "cve"])
    
    return ChangelogEntry(
        version=version,
        summary=f"Changelog for {version}",
        breaking_changes=breaking,
        bug_fixes=bugs,
        new_features=features,
        security_fixes=security,
        raw_text=content[:5000],
        source_url=url,
    )


# =============================================================================
# MAIN FETCHER CLASS
# =============================================================================

class ChangelogFetcher:
    """
    Main class for fetching changelogs.
    
    USAGE:
    ------
    fetcher = ChangelogFetcher()
    
    # Fetch for a single version
    changelog = await fetcher.fetch("org.springframework.boot:spring-boot", "3.5.3")
    
    # Fetch for multiple versions
    changelogs = await fetcher.fetch_multiple(
        "com.fasterxml.jackson.core:jackson-databind",
        ["2.19.0", "2.19.1", "2.18.0"]
    )
    """
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def fetch(
        self, 
        ga: str, 
        version: str,
        use_browser_fallback: bool = True
    ) -> Optional[ChangelogEntry]:
        """
        Fetch changelog for a specific dependency version.
        
        FLOW:
        -----
        1. Check if we have a known GitHub repo → Use GitHub API
        2. Check if we have a known changelog URL → Fetch and parse
        3. Try to guess GitHub repo from GA
        4. If all else fails and use_browser_fallback=True → Use Playwright
        
        RETURNS:
        --------
        ChangelogEntry or None if not found
        """
        # Ensure we have a session
        own_session = False
        if not self.session:
            self.session = aiohttp.ClientSession()
            own_session = True
        
        try:
            # Strategy 1: Known GitHub repo
            if ga in GITHUB_REPOS:
                result = await fetch_github_release(
                    self.session, 
                    GITHUB_REPOS[ga], 
                    version
                )
                if result:
                    return result
            
            # Strategy 2: Known changelog URL
            if ga in KNOWN_CHANGELOG_URLS:
                url = KNOWN_CHANGELOG_URLS[ga].format(version=version)
                if use_browser_fallback:
                    result = await fetch_changelog_browser(url, version)
                    if result:
                        return result
            
            # Strategy 3: Guess GitHub repo from GA
            guessed_repo = self._guess_github_repo(ga)
            if guessed_repo:
                result = await fetch_github_release(
                    self.session,
                    guessed_repo,
                    version
                )
                if result:
                    return result
            
            # Strategy 4: Browser fallback with guessed URL
            if use_browser_fallback:
                guessed_url = self._guess_changelog_url(ga, version)
                if guessed_url:
                    result = await fetch_changelog_browser(guessed_url, version)
                    if result:
                        return result
            
            return None
            
        finally:
            if own_session and self.session:
                await self.session.close()
                self.session = None
    
    async def fetch_multiple(
        self,
        ga: str,
        versions: List[str],
        use_browser_fallback: bool = True
    ) -> Dict[str, ChangelogEntry]:
        """
        Fetch changelogs for multiple versions of the same dependency.
        
        RETURNS:
        --------
        {
            "2.19.0": ChangelogEntry(...),
            "2.19.1": ChangelogEntry(...),
        }
        
        Note: Versions without changelog will be omitted from result.
        """
        results = {}
        
        async with aiohttp.ClientSession() as session:
            self.session = session
            
            for version in versions:
                changelog = await self.fetch(ga, version, use_browser_fallback)
                if changelog:
                    results[version] = changelog
        
        self.session = None
        return results
    
    def _guess_github_repo(self, ga: str) -> Optional[str]:
        """
        Try to guess GitHub repo from group:artifact.
        
        EXAMPLES:
        ---------
        "org.springframework:spring-core" → "spring-projects/spring-framework"
        "com.google.guava:guava" → "google/guava"
        """
        group, artifact = ga.split(":")
        
        # Common patterns
        patterns = [
            # org.springframework → spring-projects
            (r"org\.springframework.*", "spring-projects/spring-framework"),
            (r"org\.springframework\.boot.*", "spring-projects/spring-boot"),
            # com.google.* → google/*
            (r"com\.google\.(.+)", lambda m: f"google/{m.group(1).replace('.', '-')}"),
            # io.netty → netty/netty
            (r"io\.netty.*", "netty/netty"),
        ]
        
        for pattern, result in patterns:
            match = re.match(pattern, ga)
            if match:
                if callable(result):
                    return result(match)
                return result
        
        return None
    
    def _guess_changelog_url(self, ga: str, version: str) -> Optional[str]:
        """
        Try to guess changelog URL from GA.
        
        FALLBACK SOURCES:
        -----------------
        - Maven Central description
        - Project homepage
        """
        group, artifact = ga.split(":")
        
        # Try common URL patterns
        patterns = [
            # GitHub releases
            f"https://github.com/{group.split('.')[-1]}/{artifact}/releases/tag/v{version}",
            f"https://github.com/{group.split('.')[-1]}/{artifact}/releases/tag/{version}",
        ]
        
        # Return first pattern (could be smarter and check if URL exists)
        return patterns[0] if patterns else None


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def get_changelog(ga: str, version: str) -> Optional[Dict[str, Any]]:
    """
    Simple function to get changelog for a dependency.
    
    USAGE:
    ------
    changelog = await get_changelog("org.springframework.boot:spring-boot", "3.5.3")
    if changelog:
        print(changelog["summary"])
        print(changelog["breaking_changes"])
    """
    fetcher = ChangelogFetcher()
    async with fetcher:
        result = await fetcher.fetch(ga, version)
        if result:
            return result.to_dict()
    return None


async def get_changelogs_for_versions(
    ga: str, 
    versions: List[str]
) -> Dict[str, Dict[str, Any]]:
    """
    Get changelogs for multiple versions.
    
    USAGE:
    ------
    changelogs = await get_changelogs_for_versions(
        "com.fasterxml.jackson.core:jackson-databind",
        ["2.19.0", "2.19.1"]
    )
    """
    fetcher = ChangelogFetcher()
    async with fetcher:
        results = await fetcher.fetch_multiple(ga, versions)
        return {v: c.to_dict() for v, c in results.items()}


# =============================================================================
# TESTING
# =============================================================================

if __name__ == "__main__":
    async def test():
        print("Testing ChangelogFetcher...")
        print("=" * 60)
        
        # Test GitHub API
        print("\n1. Testing GitHub API fetch...")
        async with aiohttp.ClientSession() as session:
            result = await fetch_github_release(
                session,
                "spring-projects/spring-boot",
                "3.2.0"
            )
            if result:
                print(f"   ✓ Found: {result.summary}")
                print(f"   ✓ Breaking changes: {len(result.breaking_changes)}")
                print(f"   ✓ Bug fixes: {len(result.bug_fixes)}")
            else:
                print("   ✗ Not found")
        
        # Test full fetcher
        print("\n2. Testing full ChangelogFetcher...")
        changelog = await get_changelog("org.springframework.boot:spring-boot", "3.2.0")
        if changelog:
            print(f"   ✓ Got changelog for {changelog['version']}")
            print(f"   ✓ Source: {changelog['source_url']}")
        else:
            print("   ✗ Failed to get changelog")
        
        print("\n" + "=" * 60)
        print("Tests complete!")
    
    asyncio.run(test())

