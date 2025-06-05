from bs4 import BeautifulSoup
import aiohttp
from typing import List, Dict, Any
from .base_scraper import BaseScraper
import json
import asyncio
import re
import time

class NVDScraper(BaseScraper):
    def __init__(self):
        super().__init__()
        self.api_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.min_request_interval = 6  # NVD requires 6 seconds between requests
        self.last_request_time = 0
        
    def _parse_version(self, query: str) -> tuple:
        """Extract product and version from query"""
        # Common patterns for version numbers
        version_pattern = r'(\d+\.(?:\d+\.)*\d+)'
        product_pattern = r'^(.*?)\s*' + version_pattern
        
        version_match = re.search(version_pattern, query)
        product_match = re.search(product_pattern, query)
        
        product = product_match.group(1).strip() if product_match else None
        version = version_match.group(1) if version_match else None
        
        return product, version
        
    async def _wait_for_rate_limit(self):
        """Ensure we wait appropriate time between requests"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.min_request_interval:
            await asyncio.sleep(self.min_request_interval - time_since_last_request)
        self.last_request_time = time.time()
        
    async def search(self, query: str) -> List[Dict[str, Any]]:
        results = []
        
        try:
            product, version = self._parse_version(query)
            
            await self._wait_for_rate_limit()
            
            async with aiohttp.ClientSession() as session:
                # Try multiple search strategies
                search_attempts = [
                    # 1. Try exact version match if available
                    {'keywordSearch': query, 'versionStart': version, 'versionStartType': 'equals'} if version else None,
                    # 2. Try product name with version range if available
                    {'keywordSearch': product, 'versionStart': version, 'versionStartType': 'including'} if product and version else None,
                    # 3. Try keyword search with vulnerability keyword
                    {'keywordSearch': f"{query} vulnerability"},
                    # 4. Try original query
                    {'keywordSearch': query}
                ]
                
                for params in search_attempts:
                    if not params:
                        continue
                        
                    params['resultsPerPage'] = 20
                    
                    try:
                        headers = {
                            **self.headers,
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        }
                        
                        async with session.get(self.api_base_url, params=params, headers=headers, ssl=False) as response:
                            if response.status == 200:
                                data = await response.json()
                                vulnerabilities = data.get('vulnerabilities', [])
                                
                                if vulnerabilities:
                                    for vuln in vulnerabilities:
                                        cve = vuln.get('cve', {})
                                        
                                        # Extract CVE ID
                                        cve_id = cve.get('id', 'N/A')
                                        
                                        # Extract description
                                        descriptions = cve.get('descriptions', [])
                                        description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), 'N/A')
                                        
                                        # Extract metrics
                                        metrics = cve.get('metrics', {})
                                        cvss_v31 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                                        cvss_v30 = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {})
                                        cvss_v2 = metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {})
                                        
                                        # Use the most recent CVSS score available
                                        cvss_score = (cvss_v31.get('baseScore') or 
                                                    cvss_v30.get('baseScore') or 
                                                    cvss_v2.get('baseScore') or 
                                                    'N/A')
                                        
                                        # Extract references
                                        references = cve.get('references', [])
                                        ref_urls = []
                                        for ref in references:
                                            url = ref.get('url')
                                            tags = ref.get('tags', [])
                                            if url:
                                                ref_urls.append({
                                                    'url': url,
                                                    'tags': tags
                                                })
                                        
                                        # Check if this vulnerability matches our version if specified
                                        if version:
                                            configurations = vuln.get('configurations', [])
                                            matches_version = any(
                                                version in str(config.get('nodes', []))
                                                for config in configurations
                                            )
                                            if not matches_version:
                                                continue
                                        
                                        results.append({
                                            'title': f"{cve_id} (CVSS: {cvss_score})",
                                            'cve_id': cve_id,
                                            'description': description,
                                            'cvss_score': str(cvss_score),
                                            'source': 'NVD',
                                            'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                                            'references': ref_urls[:5],  # Include top 5 reference URLs
                                            'product': product,
                                            'version': version
                                        })
                                    
                                    # If we found results, no need to try other search attempts
                                    if results:
                                        break
                                        
                    except aiohttp.ClientError as e:
                        print(f"Error during NVD API request: {str(e)}")
                        continue
                        
        except Exception as e:
            print(f"Error searching NVD: {str(e)}")
            
        return results 