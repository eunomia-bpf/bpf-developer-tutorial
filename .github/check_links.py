#!/usr/bin/env python3
"""
Link Checker for eunomia.dev Documentation

This script checks all URLs in markdown files for availability and generates a report.
It can be run locally or as part of CI/CD pipeline.

Usage:
    python check_links.py [--fix-internal] [--output-format <format>] [--timeout <seconds>]

Options:
    --fix-internal    Attempt to fix internal eunomia.dev links
    --output-format   Output format: text, json, or markdown (default: text)
    --timeout        Request timeout in seconds (default: 10)
"""

import re
import os
import sys
import glob
import json
import argparse
import requests
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from collections import defaultdict
from datetime import datetime

# Configuration
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (eunomia.dev Link Checker) AppleWebKit/537.36'
}

# Regex patterns
URL_PATTERN = re.compile(r'https?://[^\s\)\]]+')
MARKDOWN_LINK_PATTERN = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')

# Known issues and replacements
KNOWN_REPLACEMENTS = {
    'https://eunomia.dev/tutorials/': 'https://eunomia.dev/tutorials/',
    'https://eunomia.dev/blogs/': 'https://eunomia.dev/blog/',
    'https://eunomia.dev/zh/tutorials/': 'https://eunomia.dev/tutorials/',
    'https://eunomia.dev/zh/blogs/': 'https://eunomia.dev/blog/',
}

# URLs to skip checking
SKIP_URLS = [
    'http://localhost',
    'http://127.0.0.1',
    'http://0.0.0.0',
    'https://chat.openai.com',  # Often returns 403
]

class LinkChecker:
    def __init__(self, root_dir, timeout=10):
        self.root_dir = root_dir
        self.timeout = timeout
        self.url_to_files = defaultdict(list)
        self.results = {
            'working': [],
            'broken': [],
            'skipped': [],
            'total': 0
        }
        
    def find_markdown_files(self):
        """Find all markdown files in the project"""
        md_files = []
        for pattern in ['**/*.md', '**/*.MD']:
            md_files.extend(glob.glob(os.path.join(self.root_dir, pattern), recursive=True))
        # Filter out node_modules, .git, and other irrelevant directories
        md_files = [f for f in md_files if not any(skip in f for skip in 
                    ['node_modules', '.git', 'site/', 'build/', '_build/'])]
        return sorted(md_files)
    
    def extract_urls_from_file(self, filepath):
        """Extract all URLs from a markdown file"""
        urls = set()
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Find URLs in markdown links
                for match in MARKDOWN_LINK_PATTERN.finditer(content):
                    url = match.group(2).strip()
                    if url.startswith('http'):
                        urls.add(url)
                
                # Find standalone URLs
                for match in URL_PATTERN.finditer(content):
                    url = match.group(0).rstrip('.,;:!?"\'>]')
                    urls.add(url)
                    
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
        
        return urls
    
    def should_skip_url(self, url):
        """Check if URL should be skipped"""
        return any(skip in url for skip in SKIP_URLS)
    
    def check_url(self, url):
        """Check if a URL is accessible"""
        if self.should_skip_url(url):
            return url, None, "Skipped"
            
        try:
            # Remove fragments for checking
            url_without_fragment = url.split('#')[0]
            
            # Try HEAD request first
            response = requests.head(
                url_without_fragment, 
                headers=HEADERS, 
                timeout=self.timeout, 
                allow_redirects=True
            )
            
            # If HEAD fails with 4xx/5xx, try GET
            if response.status_code >= 400:
                response = requests.get(
                    url_without_fragment, 
                    headers=HEADERS, 
                    timeout=self.timeout, 
                    allow_redirects=True
                )
            
            return url, response.status_code, None
            
        except requests.exceptions.Timeout:
            return url, None, "Timeout"
        except requests.exceptions.ConnectionError:
            return url, None, "Connection Error"
        except Exception as e:
            return url, None, str(e)
    
    def collect_urls(self):
        """Collect all URLs from markdown files"""
        print("Finding markdown files...")
        md_files = self.find_markdown_files()
        print(f"Found {len(md_files)} markdown files")
        
        print("\nExtracting URLs...")
        for md_file in md_files:
            urls = self.extract_urls_from_file(md_file)
            for url in urls:
                relative_path = os.path.relpath(md_file, self.root_dir)
                self.url_to_files[url].append(relative_path)
        
        self.results['total'] = len(self.url_to_files)
        print(f"Found {self.results['total']} unique URLs to check")
    
    def check_all_urls(self, max_workers=10):
        """Check all collected URLs concurrently"""
        print(f"\nChecking URL availability with {max_workers} workers...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.check_url, url): url 
                for url in self.url_to_files.keys()
            }
            
            checked = 0
            for future in as_completed(future_to_url):
                url, status_code, error = future.result()
                checked += 1
                
                if error == "Skipped":
                    self.results['skipped'].append({
                        'url': url,
                        'files': self.url_to_files[url]
                    })
                elif status_code and 200 <= status_code < 400:
                    self.results['working'].append({
                        'url': url,
                        'status': status_code,
                        'files': self.url_to_files[url]
                    })
                else:
                    self.results['broken'].append({
                        'url': url,
                        'status': status_code,
                        'error': error,
                        'files': self.url_to_files[url]
                    })
                
                if checked % 50 == 0:
                    print(f"Progress: {checked}/{self.results['total']} URLs checked...")
    
    def generate_report(self, output_format='text'):
        """Generate report in specified format"""
        if output_format == 'json':
            return self._generate_json_report()
        elif output_format == 'markdown':
            return self._generate_markdown_report()
        else:
            return self._generate_text_report()
    
    def _generate_text_report(self):
        """Generate plain text report"""
        report = []
        report.append("=" * 80)
        report.append("LINK CHECK REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 80)
        report.append(f"\nSUMMARY:")
        report.append(f"Total URLs checked: {self.results['total']}")
        report.append(f"Working links: {len(self.results['working'])}")
        report.append(f"Broken links: {len(self.results['broken'])}")
        report.append(f"Skipped links: {len(self.results['skipped'])}")
        report.append(f"Success rate: {len(self.results['working']) / max(1, self.results['total'] - len(self.results['skipped'])) * 100:.1f}%")
        
        if self.results['broken']:
            report.append("\n" + "=" * 80)
            report.append("BROKEN LINKS (sorted by frequency)")
            report.append("=" * 80)
            
            # Sort by number of occurrences
            sorted_broken = sorted(
                self.results['broken'], 
                key=lambda x: len(x['files']), 
                reverse=True
            )
            
            for item in sorted_broken[:50]:  # Show top 50
                report.append(f"\nURL: {item['url']}")
                if item['status']:
                    report.append(f"Status: HTTP {item['status']}")
                else:
                    report.append(f"Error: {item['error']}")
                report.append(f"Found in {len(item['files'])} file(s):")
                
                for f in item['files'][:5]:
                    report.append(f"  - {f}")
                if len(item['files']) > 5:
                    report.append(f"  ... and {len(item['files']) - 5} more files")
        
        return "\n".join(report)
    
    def _generate_markdown_report(self):
        """Generate markdown report suitable for GitHub issues"""
        report = []
        report.append("# Link Check Report")
        report.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("\n## Summary\n")
        report.append(f"- **Total URLs checked:** {self.results['total']}")
        report.append(f"- **Working links:** {len(self.results['working'])} ✅")
        report.append(f"- **Broken links:** {len(self.results['broken'])} ❌")
        report.append(f"- **Skipped links:** {len(self.results['skipped'])} ⏭️")
        report.append(f"- **Success rate:** {len(self.results['working']) / max(1, self.results['total'] - len(self.results['skipped'])) * 100:.1f}%")
        
        if self.results['broken']:
            report.append("\n## Broken Links\n")
            report.append("| URL | Status/Error | Files | Count |")
            report.append("|-----|--------------|-------|-------|")
            
            sorted_broken = sorted(
                self.results['broken'], 
                key=lambda x: len(x['files']), 
                reverse=True
            )
            
            for item in sorted_broken[:30]:
                status = f"HTTP {item['status']}" if item['status'] else item['error']
                files = f"{item['files'][0]}" if len(item['files']) == 1 else f"{item['files'][0]} (+{len(item['files'])-1} more)"
                report.append(f"| {item['url']} | {status} | {files} | {len(item['files'])} |")
        
        return "\n".join(report)
    
    def _generate_json_report(self):
        """Generate JSON report for programmatic use"""
        return json.dumps({
            'metadata': {
                'generated': datetime.now().isoformat(),
                'root_dir': self.root_dir,
                'total_urls': self.results['total']
            },
            'summary': {
                'working': len(self.results['working']),
                'broken': len(self.results['broken']),
                'skipped': len(self.results['skipped']),
                'success_rate': len(self.results['working']) / max(1, self.results['total'] - len(self.results['skipped']))
            },
            'results': self.results
        }, indent=2)
    
    def fix_internal_links(self):
        """Attempt to fix known internal link issues"""
        fixed_count = 0
        
        for broken in self.results['broken']:
            url = broken['url']
            if 'eunomia.dev' in url:
                for old_pattern, new_pattern in KNOWN_REPLACEMENTS.items():
                    if old_pattern in url:
                        new_url = url.replace(old_pattern, new_pattern)
                        print(f"Would fix: {url} -> {new_url}")
                        fixed_count += 1
                        # TODO: Actually update the files
        
        print(f"\nIdentified {fixed_count} internal links that could be fixed")


def main():
    parser = argparse.ArgumentParser(description='Check links in markdown files')
    parser.add_argument('--root-dir', default='.',
                        help='Root directory to search for markdown files')
    parser.add_argument('--fix-internal', action='store_true',
                        help='Attempt to fix internal eunomia.dev links')
    parser.add_argument('--output-format', choices=['text', 'json', 'markdown'],
                        default='text', help='Output format for the report')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds')
    parser.add_argument('--max-workers', type=int, default=10,
                        help='Maximum number of concurrent requests')
    parser.add_argument('--output-file', help='Save report to file')
    
    args = parser.parse_args()
    
    # Create checker instance
    checker = LinkChecker(args.root_dir, args.timeout)
    
    # Collect and check URLs
    checker.collect_urls()
    checker.check_all_urls(args.max_workers)
    
    # Generate report
    report = checker.generate_report(args.output_format)
    
    # Output report
    if args.output_file:
        with open(args.output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\nReport saved to: {args.output_file}")
    else:
        print("\n" + report)
    
    # Fix internal links if requested
    if args.fix_internal:
        checker.fix_internal_links()
    
    # Exit with error code if broken links found
    if checker.results['broken']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()