from bs4 import BeautifulSoup
import aiohttp
from typing import List, Dict, Any
from .base_scraper import BaseScraper
import re
from urllib.parse import quote
import asyncio
import time

class CVEDetailsScraper(BaseScraper):
    def __init__(self):
        super().__init__()
        self.base_url = "https://www.cvedetails.com"
        self.search_url = f"{self.base_url}/vulnerability-search.php"
        self.min_request_interval = 5  # Increased delay to avoid rate limiting
        self.last_request_time = 0
        
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
            await self._wait_for_rate_limit()
            web_results = await self._search_web(query)
            results.extend(web_results)
                
        except Exception as e:
            print(f"Error searching CVE Details: {str(e)}")
            
        return results
        
    async def _search_web(self, query: str) -> List[Dict[str, Any]]:
        """Search using web interface"""
        results = []
        product, version = self._parse_product_version(query)
        
        # Construct search URL
        search_params = {
            'vendor': '',
            'product': product if product else query,
            'version': version if version else '',
            'hasexp': 0,
            'opec': 0,
            'opov': 0,
            'opcsrf': 0,
            'opfileinc': 0,
            'opgpriv': 0,
            'opsqli': 0,
            'opxss': 0,
            'opmemc': 0,
            'opbyp': 0,
            'opginf': 0,
            'opdirt': 0,
            'opconf': 0,
            'opdec': 0,
            'opdos': 0,
            'orderby': 3,  # Order by CVSS score
            'order': 'DESC'
        }
        
        headers = {
            **self.headers,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Referer': self.base_url
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.search_url, params=search_params, headers=headers, ssl=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        soup = BeautifulSoup(content, 'html.parser')
                        
                        # Find vulnerability table
                        vuln_table = soup.find('table', {'class': 'searchresults'})
                        if not vuln_table:
                            return results
                            
                        for row in vuln_table.find_all('tr')[1:]:  # Skip header row
                            try:
                                cols = row.find_all('td')
                                if len(cols) >= 7:
                                    cve_id = cols[1].find('a')
                                    if not cve_id:
                                        continue
                                        
                                    cve_id = cve_id.text.strip()
                                    description = cols[6].text.strip()
                                    cvss_score = cols[7].text.strip() if len(cols) > 7 else 'N/A'
                                    vuln_type = cols[4].text.strip()
                                    
                                    # Get the details page URL
                                    details_url = f"{self.base_url}/cve/{cve_id}"
                                    
                                    # Wait for rate limit before fetching details
                                    await self._wait_for_rate_limit()
                                    
                                    # Get additional details from the CVE page
                                    try:
                                        async with session.get(details_url, headers=headers, ssl=False) as details_response:
                                            if details_response.status == 200:
                                                details_content = await details_response.text()
                                                details_soup = BeautifulSoup(details_content, 'html.parser')
                                                
                                                # Extract references
                                                ref_table = details_soup.find('table', {'class': 'listtable'})
                                                references = []
                                                if ref_table:
                                                    for ref_row in ref_table.find_all('tr')[1:]:
                                                        ref_cols = ref_row.find_all('td')
                                                        if len(ref_cols) >= 2:
                                                            ref_url = ref_cols[0].find('a')
                                                            if ref_url and ref_url.get('href'):
                                                                references.append({
                                                                    'url': ref_url['href'],
                                                                    'source': 'CVE Details Reference'
                                                                })
                                                
                                                results.append({
                                                    'title': f"CVE Details: {cve_id}",
                                                    'description': description,
                                                    'source': 'CVE Details',
                                                    'url': details_url,
                                                    'cvss_score': cvss_score,
                                                    'cve_id': cve_id,
                                                    'type': vuln_type,
                                                    'references': references[:5]  # Include top 5 references
                                                })
                                                
                                    except Exception as e:
                                        print(f"Error fetching CVE details for {cve_id}: {str(e)}")
                                        # Add basic information even if details fetch fails
                                        results.append({
                                            'title': f"CVE Details: {cve_id}",
                                            'description': description,
                                            'source': 'CVE Details',
                                            'url': details_url,
                                            'cvss_score': cvss_score,
                                            'cve_id': cve_id,
                                            'type': vuln_type
                                        })
                                        
                            except Exception as e:
                                print(f"Error parsing vulnerability row: {str(e)}")
                                continue
                                
            except Exception as e:
                print(f"Error accessing CVE Details: {str(e)}")
                
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