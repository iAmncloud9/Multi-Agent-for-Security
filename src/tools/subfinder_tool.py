import subprocess
import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Union
from utils.validator import validate_domain

class SubfinderTool:
    """Tool class for subfinder subdomain discovery"""
    
    @staticmethod
    def extract_domain(input_url: str) -> str:
        """Extract domain from URL if needed"""
        parsed = urlparse(input_url)
        if parsed.scheme:
            return parsed.netloc
        return input_url
    
    def find_subdomains(self, domain: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run subfinder to discover subdomains
        
        Args:
            domain: Target domain to find subdomains
            options: Additional options for subfinder
            
        Returns:
            Dictionary with results or error information
        """
        try:
            # Validate and extract domain
            domain = self.extract_domain(domain)
            if not validate_domain(domain):
                return {
                    'status': 'error',
                    'message': f"Invalid domain name: {domain}",
                    'subdomains': []
                }
            
            # Build command
            cmd = ["subfinder", "-d", domain, "-silent"]
            
            # Add options if provided
            if options:
                if options.get('timeout'):
                    cmd.extend(['-timeout', str(options['timeout'])])
                if options.get('recursive'):
                    cmd.append('-recursive')
                if options.get('max_depth'):
                    cmd.extend(['-max-depth', str(options['max_depth'])])
            
            # Execute subfinder
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            # Process output
            if result.stdout.strip():
                subdomains = result.stdout.strip().split('\n')
                return {
                    'status': 'success',
                    'domain': domain,
                    'subdomains': subdomains,
                    'count': len(subdomains)
                }
            else:
                return {
                    'status': 'success',
                    'domain': domain,
                    'subdomains': [],
                    'count': 0,
                    'message': 'No subdomains found'
                }
                
        except subprocess.CalledProcessError as e:
            return {
                'status': 'error',
                'domain': domain,
                'message': f"Subfinder execution failed: {e.stderr.strip()}",
                'subdomains': []
            }
        except Exception as e:
            return {
                'status': 'error',
                'domain': domain,
                'message': f"Unexpected error: {str(e)}",
                'subdomains': []
            }
    
    def run_with_options(self, domain: str, sources: List[str] = None, 
                         timeout: int = 30, recursive: bool = False) -> Dict[str, Any]:
        """
        Run subfinder with specific options
        
        Args:
            domain: Target domain
            sources: List of sources to use
            timeout: Timeout in seconds
            recursive: Enable recursive subdomain discovery
            
        Returns:
            Dictionary with results
        """
        options = {
            'timeout': timeout,
            'recursive': recursive
        }
        
        if sources:
            options['sources'] = sources
            
        return self.find_subdomains(domain, options)