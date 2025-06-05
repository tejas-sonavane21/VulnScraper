from bs4 import BeautifulSoup
import aiohttp
from typing import List, Dict, Any
from .base_scraper import BaseScraper
import re
from urllib.parse import quote

class CVEOrgScraper(BaseScraper):
    def __init__(self):
        super().__init__()
        self.api_url = "https://www.cve.org/api/cves"  # API endpoint
        self.web_url = "https://www.cve.org/cverecord"  # Web interface
        self.min_request_interval = 2
        
    async def search(self, query: str) -> List[Dict[str, Any]]:
        """Search CVE.org for vulnerabilities"""
        results = []
        
        try:
            # First try API search
            api_results = await self._search_api(query)
            if api_results:
                results.extend(api_results)
                
            # If API fails or no results, try web interface
            if not results:
                web_results = await self._search_web(query)
                results.extend(web_results)
                
        except Exception as e:
            print(f"Error searching CVE.org: {str(e)}")
            
        return results
        
    async def _search_api(self, query: str) -> List[Dict[str, Any]]:
        """Search using CVE.org API"""
        results = []
        
        # Extract version if present
        version_match = re.search(r'(\d+\.(?:\d+\.)*\d+)', query)
        version = version_match.group(1) if version_match else None
        
        # API parameters
        params = {
            'keyword': query,
            'resultsPerPage': 20,
            'startIndex': 0
        }
        
        response_data = await self._make_request(self.api_url, params=params)
        
        if response_data and isinstance(response_data, dict):
            vulnerabilities = response_data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                # Skip if version specified and doesn't match
                if version and version not in str(vuln):
                    continue
                    
                cve_id = vuln.get('cveId')
                if not cve_id:
                    continue
                    
                # Get detailed information
                detail_url = f"{self.api_url}/{cve_id}"
                detail_data = await self._make_request(detail_url)
                
                if detail_data:
                    results.append(self._parse_vulnerability(detail_data))
                    
        return results
        
    async def _search_web(self, query: str) -> List[Dict[str, Any]]:
        """Search using CVE.org web interface"""
        results = []
        encoded_query = quote(query)
        search_url = f"https://www.cve.org/search?query={encoded_query}"
        
        response_data = await self._make_request(search_url)
        
        if response_data and 'text' in response_data:
            soup = BeautifulSoup(response_data['text'], 'html.parser')
            
            # Find vulnerability entries
            for entry in soup.find_all('div', {'class': 'cve-record'}):
                try:
                    cve_id = entry.find('span', {'class': 'cve-id'})
                    description = entry.find('div', {'class': 'description'})
                    severity = entry.find('div', {'class': 'severity'})
                    
                    if cve_id:
                        cve_id = cve_id.text.strip()
                        results.append({
                            'title': f"CVE.org: {cve_id}",
                            'cve_id': cve_id,
                            'description': description.text.strip() if description else 'No description available',
                            'severity': severity.text.strip() if severity else 'N/A',
                            'source': 'CVE.org',
                            'url': f"{self.web_url}?id={cve_id}",
                            'references': [
                                {'url': f"{self.web_url}?id={cve_id}", 'source': 'CVE.org Entry'},
                                {'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}", 'source': 'NVD Entry'}
                            ]
                        })
                        
                except Exception as e:
                    print(f"Error parsing CVE.org entry: {str(e)}")
                    continue
                    
        return results
        
    def _parse_vulnerability(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse vulnerability data from API response"""
        cve_id = data.get('cveId', 'N/A')
        description = data.get('description', {}).get('description', 'No description available')
        severity = data.get('metrics', {}).get('cvssV3', {}).get('baseScore', 'N/A')
        
        return {
            'title': f"CVE.org: {cve_id}",
            'cve_id': cve_id,
            'description': description,
            'severity': str(severity),
            'source': 'CVE.org',
            'url': f"{self.web_url}?id={cve_id}",
            'references': [
                {'url': f"{self.web_url}?id={cve_id}", 'source': 'CVE.org Entry'},
                {'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}", 'source': 'NVD Entry'}
            ]
        } 