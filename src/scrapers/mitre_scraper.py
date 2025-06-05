from bs4 import BeautifulSoup
import aiohttp
from typing import List, Dict, Any
from .base_scraper import BaseScraper
import asyncio
import re

class MitreScraper(BaseScraper):
    def __init__(self):
        super().__init__()
        self.search_url = "https://cve.mitre.org/cgi-bin/cvekey.cgi"
        
    async def search(self, query: str) -> List[Dict[str, Any]]:
        results = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Search Mitre CVE database
                params = {'keyword': query}
                
                async with session.get(self.search_url, params=params, headers=self.headers) as response:
                    if response.status == 200:
                        content = await response.text()
                        soup = BeautifulSoup(content, 'html.parser')
                        
                        # Find all CVE entries in the table
                        cve_table = soup.find('div', {'id': 'TableWithRules'})
                        if cve_table:
                            cve_rows = cve_table.find_all('tr')[1:]  # Skip header row
                            
                            for row in cve_rows[:10]:  # Limit to top 10 results
                                cols = row.find_all('td')
                                if len(cols) >= 2:
                                    cve_id = cols[0].text.strip()
                                    description = cols[1].text.strip()
                                    
                                    # Get the CVE details page for more information
                                    cve_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
                                    try:
                                        async with session.get(cve_url, headers=self.headers) as cve_response:
                                            if cve_response.status == 200:
                                                cve_content = await cve_response.text()
                                                cve_soup = BeautifulSoup(cve_content, 'html.parser')
                                                
                                                # Extract references
                                                ref_table = cve_soup.find('table', {'id': 'refs'})
                                                references = []
                                                if ref_table:
                                                    ref_rows = ref_table.find_all('tr')[1:]
                                                    for ref_row in ref_rows:
                                                        ref_cols = ref_row.find_all('td')
                                                        if len(ref_cols) >= 2:
                                                            ref_url = ref_cols[1].find('a')
                                                            if ref_url:
                                                                references.append({
                                                                    'url': ref_url['href'],
                                                                    'source': ref_cols[0].text.strip()
                                                                })
                                                
                                                results.append({
                                                    'title': cve_id,
                                                    'cve_id': cve_id,
                                                    'description': description,
                                                    'source': 'MITRE',
                                                    'url': cve_url,
                                                    'references': references[:5]  # Include top 5 references
                                                })
                                    except Exception as e:
                                        print(f"Error fetching CVE details for {cve_id}: {str(e)}")
                                        # Still add basic information even if details fetch fails
                                        results.append({
                                            'title': cve_id,
                                            'cve_id': cve_id,
                                            'description': description,
                                            'source': 'MITRE',
                                            'url': cve_url
                                        })
                                        
        except Exception as e:
            print(f"Error searching MITRE: {str(e)}")
            
        return results 