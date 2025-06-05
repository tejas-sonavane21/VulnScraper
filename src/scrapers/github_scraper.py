from bs4 import BeautifulSoup
import aiohttp
from typing import List, Dict, Any, Optional
from .base_scraper import BaseScraper
import asyncio
import re
import json
import os
from urllib.parse import quote

class GitHubScraper(BaseScraper):
    def __init__(self, github_token: Optional[str] = None):
        """
        Initialize GitHub scraper with optional token
        
        Args:
            github_token (Optional[str]): GitHub API token. If not provided, 
                                        will check GITHUB_TOKEN environment variable.
                                        If neither is available, will use unauthenticated access.
        """
        super().__init__()
        self.api_url = "https://api.github.com/search/repositories"
        self.advisory_url = "https://api.github.com/search/security-advisories"
        self.web_search_url = "https://github.com/search"
        self.headers.update({
            'Accept': 'application/vnd.github.v3+json'
        })
        
        # Validate GitHub token
        if github_token is None or not isinstance(github_token, str) or not github_token.strip():
            # Try environment variable as backup
            github_token = os.environ.get('GITHUB_TOKEN', '')
            
        # Only set token if it's a valid non-empty string
        if isinstance(github_token, str) and github_token.strip():
            self.github_token = github_token.strip()
            self.headers['Authorization'] = f"token {self.github_token}"
            self.api_rate_limit = 5000  # Authenticated rate limit
            print("Using authenticated GitHub API access")
        else:
            self.github_token = None
            self.api_rate_limit = 60    # Unauthenticated rate limit
            print("Using unauthenticated GitHub API access - consider adding a token for higher rate limits")
            
        self.api_calls = 0
        self.last_reset = asyncio.get_event_loop().time()
        
    async def search(self, query: str) -> List[Dict[str, Any]]:
        """Main search method with fallback chain"""
        results = []
        
        try:
            # First attempt: API search (authenticated or unauthenticated)
            api_results = await self._search_api(query)
            if api_results:
                results.extend(api_results)
                
            # If API search failed or hit rate limits, try web scraping
            if not results:
                web_results = await self._search_web(query)
                results.extend(web_results)
                
        except Exception as e:
            print(f"Error in GitHub search: {str(e)}")
            
        return results
        
    async def _search_api(self, query: str) -> List[Dict[str, Any]]:
        """Search using GitHub API with rate limit handling"""
        results = []
        
        # Check rate limiting
        if self.api_calls >= self.api_rate_limit:
            # Check if rate limit has reset
            now = asyncio.get_event_loop().time()
            if now - self.last_reset < 3600:  # Within the hour
                print("GitHub API rate limit exceeded")
                return []
            else:
                self.api_calls = 0
                self.last_reset = now
                
        try:
            # Search for exploit repositories
            repo_results = await self._search_repos_api(query)
            results.extend(repo_results)
            
            # Search security advisories if we haven't hit rate limits
            if self.api_calls < self.api_rate_limit:
                advisory_results = await self._search_advisories_api(query)
                results.extend(advisory_results)
                
        except Exception as e:
            if "rate limit exceeded" in str(e).lower():
                print("GitHub API rate limit exceeded during search")
                return []
            raise
            
        return results
        
    async def _search_repos_api(self, query: str) -> List[Dict[str, Any]]:
        """Search repositories using GitHub API"""
        results = []
        
        repo_params = {
            'q': f"{query} in:name,description,readme exploit POC CVE",
            'sort': 'stars',
            'order': 'desc',
            'per_page': 10
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(self.api_url, params=repo_params, headers=self.headers) as response:
                self.api_calls += 1
                
                if response.status == 200:
                    data = await response.json()
                    repos = data.get('items', [])
                    
                    for repo in repos:
                        # Get README content if within rate limits
                        readme_text = "No README available"
                        if self.api_calls < self.api_rate_limit:
                            readme_url = f"{repo['url']}/readme"
                            try:
                                async with session.get(readme_url, headers=self.headers) as readme_response:
                                    self.api_calls += 1
                                    if readme_response.status == 200:
                                        readme_data = await readme_response.json()
                                        readme_content = readme_data.get('content', '')
                                        import base64
                                        readme_text = base64.b64decode(readme_content).decode('utf-8')
                            except:
                                pass
                                
                        results.append({
                            'title': f"GitHub: {repo['full_name']}",
                            'description': (repo['description'] or "No description") + "\n\nREADME Preview:\n" + 
                                         readme_text[:500] + "..." if len(readme_text) > 500 else readme_text,
                            'source': 'GitHub',
                            'url': repo['html_url'],
                            'stars': repo['stargazers_count'],
                            'last_updated': repo['updated_at'],
                            'references': [
                                {'url': repo['html_url'], 'source': 'GitHub Repository'},
                                {'url': f"{repo['html_url']}/issues", 'source': 'Issues'},
                                {'url': f"{repo['html_url']}/releases", 'source': 'Releases'}
                            ]
                        })
                        
        return results
        
    async def _search_advisories_api(self, query: str) -> List[Dict[str, Any]]:
        """Search security advisories using GitHub API"""
        results = []
        product, version = self._parse_product_version(query)
        
        if product:
            advisory_params = {
                'q': f"{product} in:vulnerability",
                'type': 'SECURITY_ADVISORY',
                'per_page': 10
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.advisory_url, params=advisory_params, headers=self.headers) as response:
                    self.api_calls += 1
                    
                    if response.status == 200:
                        data = await response.json()
                        advisories = data.get('items', [])
                        
                        for advisory in advisories:
                            if version and version not in str(advisory.get('vulnerableVersionRange', '')):
                                continue
                                
                            results.append({
                                'title': f"GitHub Advisory: {advisory['ghsaId']}",
                                'description': advisory.get('summary', 'No summary available'),
                                'source': 'GitHub Advisory',
                                'url': advisory.get('permalink', ''),
                                'severity': advisory.get('severity', 'N/A'),
                                'published': advisory.get('publishedAt', 'N/A'),
                                'references': [
                                    {'url': ref, 'source': 'Advisory Reference'}
                                    for ref in advisory.get('references', [])
                                ]
                            })
                            
        return results
        
    async def _search_web(self, query: str) -> List[Dict[str, Any]]:
        """Fallback to web scraping when API is rate limited"""
        results = []
        
        try:
            # Search repositories through web interface
            encoded_query = quote(f"{query} exploit POC CVE")
            search_url = f"{self.web_search_url}?q={encoded_query}&type=repositories&s=stars&o=desc"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(search_url, headers=self.headers) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Find repository results
                        repo_list = soup.find('ul', {'class': 'repo-list'})
                        if repo_list:
                            for repo in repo_list.find_all('li', {'class': 'repo-list-item'}, limit=10):
                                try:
                                    title_elem = repo.find('a', {'class': 'v-align-middle'})
                                    desc_elem = repo.find('p', {'class': 'mb-1'})
                                    stars_elem = repo.find('a', {'class': 'Link--muted'})
                                    
                                    if title_elem:
                                        repo_url = f"https://github.com{title_elem['href']}"
                                        
                                        # Get README content
                                        readme_url = f"{repo_url}/blob/master/README.md"
                                        readme_text = "No README available"
                                        try:
                                            async with session.get(readme_url, headers=self.headers) as readme_response:
                                                if readme_response.status == 200:
                                                    readme_html = await readme_response.text()
                                                    readme_soup = BeautifulSoup(readme_html, 'html.parser')
                                                    article = readme_soup.find('article')
                                                    if article:
                                                        readme_text = article.get_text()[:500] + "..."
                                        except:
                                            pass
                                            
                                        results.append({
                                            'title': f"GitHub: {title_elem.text.strip()}",
                                            'description': (desc_elem.text.strip() if desc_elem else "No description") + 
                                                         "\n\nREADME Preview:\n" + readme_text,
                                            'source': 'GitHub',
                                            'url': repo_url,
                                            'stars': stars_elem.text.strip() if stars_elem else 'N/A',
                                            'references': [
                                                {'url': repo_url, 'source': 'GitHub Repository'},
                                                {'url': f"{repo_url}/issues", 'source': 'Issues'},
                                                {'url': f"{repo_url}/releases", 'source': 'Releases'}
                                            ]
                                        })
                                        
                                except Exception as e:
                                    print(f"Error processing repository: {str(e)}")
                                    continue
                                    
        except Exception as e:
            print(f"Error in web scraping fallback: {str(e)}")
            
        return results
        
    def _parse_product_version(self, query: str) -> tuple:
        """Extract product and version from query"""
        version_pattern = r'(\d+\.(?:\d+\.)*\d+)'
        product_pattern = r'^(.*?)\s*' + version_pattern
        
        version_match = re.search(version_pattern, query)
        product_match = re.search(product_pattern, query)
        
        product = product_match.group(1).strip() if product_match else None
        version = version_match.group(1) if version_match else None
        
        return product, version 