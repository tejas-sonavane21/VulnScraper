from setuptools import setup, find_packages

setup(
    name="vulnscraper",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'requests==2.31.0',
        'beautifulsoup4==4.12.2',
        'rich==13.7.0',
        'aiohttp==3.9.1',
        'python-dotenv==1.0.0',
        'certifi==2024.2.2',
        'urllib3==2.2.0'
    ],
    entry_points={
        'console_scripts': [
            'vulnscraper=src.vuln_scraper:main',
        ],
    },
) 