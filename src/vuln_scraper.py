import asyncio
import argparse
from typing import List, Dict, Any
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TimeRemainingColumn, SpinnerColumn
from rich.panel import Panel
from rich.text import Text
import json
from .scrapers.exploit_db_scraper import ExploitDBScraper
from .scrapers.cve_details_scraper import CVEDetailsScraper
from .scrapers.nvd_scraper import NVDScraper
from .scrapers.mitre_scraper import MitreScraper
from .scrapers.github_scraper import GitHubScraper
from .scrapers.cve_org_scraper import CVEOrgScraper

class VulnScraper:
    def __init__(self):
        self.console = Console()
        
        # GitHub token configuration
        # To use authenticated GitHub access, replace None with your token as a string
        # Example: github_token = "ghp_your_token_here"
        github_token = None  # Keep as None for unauthenticated access
        
        self.scrapers = [
            MitreScraper(),    # Legacy source (will be retired)
            GitHubScraper(github_token),   # Pass token directly, not as keyword argument
            NVDScraper(),      # Primary source (official API)
            CVEOrgScraper(),   # New official CVE source (replacement for MITRE)
            ExploitDBScraper(),
            CVEDetailsScraper()
        ]

    async def search_all(self, query: str) -> List[Dict[str, Any]]:
        all_results = []
        successful_sources = {}  # Changed to dict to store count of results
        failed_sources = {}
        
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=self.console
        )
        
        progress.start()
        task = progress.add_task("", total=len(self.scrapers))
        
        try:
            for scraper in self.scrapers:
                # Update progress description with current scraper
                scraper_name = scraper.__class__.__name__
                progress.update(task, description=f"Searching {scraper_name.replace('Scraper', '')}...")
                
                try:
                    results = await scraper.search(query)
                    if results:
                        all_results.extend(results)
                        successful_sources[scraper_name.replace('Scraper', '')] = len(results)
                except Exception as e:
                    error_msg = str(e)
                    failed_sources[scraper_name] = error_msg
                
                progress.advance(task)
            
            # Update final description to show completion
            progress.update(task, description="Search completed")
        finally:
            progress.stop()
        
        # Display summary of successful sources with result counts
        if successful_sources:
            source_summary = ", ".join([f"{source} ({count})" for source, count in successful_sources.items()])
            self.console.print(f"\n[green]Successfully retrieved data from: {source_summary}[/green]")
        
        # Remove duplicates based on CVE ID
        seen_cves = set()
        unique_results = []
        for result in all_results:
            cve_id = result.get('cve_id')
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                unique_results.append(result)
            elif not cve_id:
                unique_results.append(result)
        
        return unique_results

    def display_results(self, results: List[Dict[str, Any]]):
        if not results:
            self.console.print("[yellow]No results found.[/yellow]")
            return

        # Group results by source
        grouped_results = {}
        for result in results:
            source = result['source']
            if source not in grouped_results:
                grouped_results[source] = []
            grouped_results[source].append(result)

        # Display results by source
        for source, source_results in grouped_results.items():
            self.console.print(f"\n[bold magenta]{source} Results:[/bold magenta]")
            
            for result in source_results:
                # Create result panel
                content = []
                
                # Title/CVE ID
                title = result.get('title', result.get('cve_id', 'N/A'))
                content.append(f"[bold cyan]{title}[/bold cyan]")
                
                # CVSS Score if available
                if 'cvss_score' in result:
                    score = float(result['cvss_score']) if result['cvss_score'] != 'N/A' else 0
                    score_color = 'red' if score >= 7 else 'yellow' if score >= 4 else 'green'
                    content.append(f"[bold {score_color}]CVSS Score: {result['cvss_score']}[/bold {score_color}]")
                elif 'severity' in result:
                    content.append(f"[bold]Severity: {result['severity']}[/bold]")
                
                # Product and Version if available
                if 'product' in result and 'version' in result and result['product'] and result['version']:
                    content.append(f"\n[bold]Product:[/bold] {result['product']} {result['version']}")
                
                # Description
                description = result.get('description', 'N/A')
                content.append(f"\n{description}")
                
                # URL
                content.append(f"\n[blue]URL: {result['url']}[/blue]")
                
                # References if available
                if 'references' in result and result['references']:
                    content.append("\n[bold]References:[/bold]")
                    for ref in result['references'][:3]:  # Show top 3 references
                        if isinstance(ref, dict):
                            ref_text = f"[blue]- {ref['url']}[/blue]"
                            if 'tags' in ref:
                                ref_text += f" ({', '.join(ref['tags'])})"
                            elif 'source' in ref:
                                ref_text += f" ({ref['source']})"
                            content.append(ref_text)
                        else:
                            content.append(f"[blue]- {ref}[/blue]")
                
                panel = Panel(
                    Text.from_markup('\n'.join(content)),
                    border_style="bright_black",
                    padding=(1, 2)
                )
                self.console.print(panel)

    def export_results(self, results: List[Dict[str, Any]], output_file: str):
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        self.console.print(f"[green]Results exported to {output_file}[/green]")

def main():
    parser = argparse.ArgumentParser(description='Vulnerability and Exploit Scraper')
    parser.add_argument('--search', '-s', required=True, help='Search query')
    parser.add_argument('--output', '-o', help='Output file for results (JSON format)')
    args = parser.parse_args()

    scraper = VulnScraper()
    console = Console()

    try:
        results = asyncio.run(scraper.search_all(args.search))
        scraper.display_results(results)
        
        if args.output:
            scraper.export_results(results, args.output)
            
    except KeyboardInterrupt:
        console.print("\n[red]Search cancelled by user[/red]")
    except Exception as e:
        console.print(f"[red]An error occurred: {str(e)}[/red]")

if __name__ == "__main__":
    main() 