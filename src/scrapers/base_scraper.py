from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import aiohttp
import asyncio
import random
import ssl
import certifi
import warnings
from contextlib import asynccontextmanager

class BaseScraper(ABC):
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
        }
        self.session: Optional[aiohttp.ClientSession] = None
        self.last_request_time = 0
        self.min_request_interval = 2  # Minimum seconds between requests
        
    @asynccontextmanager
    async def get_session(self):
        """Context manager for handling session lifecycle"""
        if not self.session:
            self.session = aiohttp.ClientSession()
        try:
            yield self.session
        finally:
            if self.session:
                await self.session.close()
                self.session = None
                
    async def _make_request(self, url: str, params: Dict[str, Any] = None, method: str = 'GET') -> Dict[str, Any]:
        """Make a rate-limited request with proper browser emulation"""
        # Calculate delay needed for rate limiting
        now = asyncio.get_event_loop().time()
        time_since_last = now - self.last_request_time
        if time_since_last < self.min_request_interval:
            delay = self.min_request_interval - time_since_last + random.uniform(0.1, 1.0)
            await asyncio.sleep(delay)
            
        async with self.get_session() as session:
            try:
                if method == 'GET':
                    async with session.get(url, params=params, headers=self.headers, ssl=False) as response:
                        self.last_request_time = asyncio.get_event_loop().time()
                        
                        if response.status == 429:  # Too Many Requests
                            retry_after = response.headers.get('Retry-After', '60')
                            await asyncio.sleep(float(retry_after))
                            return await self._make_request(url, params, method)
                            
                        if response.headers.get('Content-Type', '').startswith('application/json'):
                            return await response.json()
                        else:
                            return {'text': await response.text()}
                            
            except Exception as e:
                print(f"Error making request to {url}: {str(e)}")
                return {}
            
    @abstractmethod
    async def search(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for vulnerabilities based on the query
        
        Args:
            query (str): Search query (e.g., "apache 2.4.49 vulnerability")
            
        Returns:
            List[Dict[str, Any]]: List of found vulnerabilities with their details
        """
        pass
    
    async def fetch_page(self, session: aiohttp.ClientSession, url: str) -> str:
        """
        Fetch a page with error handling and retries
        """
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # First try: Direct HTTPS request without proxy
                async with session.get(
                    url,
                    headers=self.headers,
                    timeout=15,
                    ssl=ssl.create_default_context(cafile=certifi.where()),
                    proxy=None
                ) as response:
                    if response.status == 200:
                        return await response.text()
                    
                # Second try: Use requests library as fallback
                if attempt == 1:
                    try:
                        response = requests.get(
                            url,
                            headers={'User-Agent': self.headers['User-Agent']},
                            verify=False,
                            timeout=15
                        )
                        if response.status_code == 200:
                            return response.text
                    except Exception as e:
                        print(f"Fallback request failed for {url}: {str(e)}")
                
                # Third try: Use proxy
                if attempt == 2:
                    proxy = await self.proxy_handler.get_proxy()
                    if proxy:
                        async with session.get(
                            url,
                            headers={'User-Agent': self.headers['User-Agent']},
                            timeout=15,
                            ssl=ssl.create_default_context(cafile=certifi.where()),
                            proxy=proxy
                        ) as response:
                            if response.status == 200:
                                return await response.text()
                
                # Handle rate limiting
                if response.status == 429:
                    wait_time = 2 ** attempt
                    print(f"Rate limited, waiting {wait_time} seconds...")
                    await asyncio.sleep(wait_time)
                    continue
                    
            except aiohttp.ClientSSLError as ssl_err:
                print(f"SSL Error for {url}: {str(ssl_err)}")
                # Try without SSL verification on next attempt
                ssl_context = ssl.create_default_context(cafile=certifi.where())
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                await asyncio.sleep(1)
                
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                print(f"Connection error for {url}: {str(e)}")
                await asyncio.sleep(1)
                
            except Exception as e:
                print(f"Error fetching {url}: {str(e)}")
                await asyncio.sleep(1)
                
        return ""  # Return empty string if all attempts fail 