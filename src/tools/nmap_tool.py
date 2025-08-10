import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
import nmap
from datetime import datetime
import socket
from utils.validator import validate_ip, validate_host

class NmapTool:
    """Tool class for Nmap port scanning"""
    
    def __init__(self):
        """Initialize Nmap scanner"""
        self.nm = nmap.PortScanner()
    
    
    def _prepare_nmap_args(self, scan_type: str, port_range: str) -> str:
        """Prepare nmap arguments based on scan type"""
        base_args = f"-p {port_range}"
        
        if scan_type.lower() == "syn":
            return f"{base_args} -sS -sV"
        elif scan_type.lower() == "udp":
            return f"{base_args} -sU"
        elif scan_type.lower() == "tcp":
            return f"{base_args} -sT -sV"
        else:
            return f"{base_args} -sT -sV"  # Default to TCP
    
    def _parse_scan_results(self, scan_result: Dict, target: str) -> Dict[str, Any]:
        """Parse nmap scan results into structured format"""
        try:
            results = {
                'host_info': {},
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'summary': {}
            }
            
            if target not in self.nm.all_hosts():
                results['summary']['status'] = 'host_not_found'
                return results
            
            host_info = self.nm[target]
            
            # Host information
            results['host_info'] = {
                'ip': target,
                'hostname': host_info.hostname() if host_info.hostname() else 'N/A',
                'state': host_info.state(),
                'protocols': list(host_info.all_protocols())
            }
            
            # Port information
            for protocol in host_info.all_protocols():
                ports = host_info[protocol].keys()
                
                for port in ports:
                    port_info = {
                        'port': port,
                        'protocol': protocol,
                        'state': host_info[protocol][port]['state'],
                        'service': host_info[protocol][port].get('name', 'unknown'),
                        'version': host_info[protocol][port].get('version', ''),
                        'product': host_info[protocol][port].get('product', ''),
                        'extrainfo': host_info[protocol][port].get('extrainfo', '')
                    }
                    
                    if port_info['state'] == 'open':
                        results['open_ports'].append(port_info)
                    elif port_info['state'] == 'closed':
                        results['closed_ports'].append(port_info)
                    elif port_info['state'] in ['filtered', 'open|filtered']:
                        results['filtered_ports'].append(port_info)
            
            # Summary
            results['summary'] = {
                'total_open': len(results['open_ports']),
                'total_closed': len(results['closed_ports']),
                'total_filtered': len(results['filtered_ports']),
                'scan_status': 'completed'
            }
            
            return results
            
        except Exception as e:
            raise Exception(f"Failed to parse scan results: {str(e)}")
    
    def scan_ports(self, target: str, port_range: str = "1-1000", 
                   scan_type: str = "tcp") -> Dict[str, Any]:
        """
        Run nmap to scan ports
        
        Args:
            target: IP address or hostname to scan
            port_range: Port range to scan (default: 1-1000)
            scan_type: Type of scan (tcp, udp, syn)
            
        Returns:
            Dictionary with results or error information
        """
        try:
            # Validate target
            if not (validate_ip(target) or validate_host(target)):
                return {
                    'status': 'error',
                    'message': f"Invalid target: {target}",
                    'results': {}
                }
            
            # Prepare nmap arguments based on scan type
            nmap_args = self._prepare_nmap_args(scan_type, port_range)
            
            # Execute the scan
            self.nm.scan(target, arguments=nmap_args)
            
            # Parse and format results
            scan_results = self._parse_scan_results(self.nm, target)
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': scan_type,
                'port_range': port_range,
                'results': scan_results,
                'timestamp': datetime.now().isoformat()
            }
            
        except nmap.PortScannerError as e:
            return {
                'status': 'error',
                'message': f"Nmap scan error: {str(e)}",
                'target': target
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f"Unexpected error: {str(e)}",
                'target': target
            }
    
    def quick_scan(self, target: str) -> Dict[str, Any]:
        """
        Perform a quick scan of most common ports
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            Dictionary with results
        """
        return self.scan_ports(target, port_range="22,23,25,53,80,110,443,993,995", scan_type="tcp")
    
    def intense_scan(self, target: str) -> Dict[str, Any]:
        """
        Perform an intensive scan with service detection
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            Dictionary with results
        """
        return self.scan_ports(target, port_range="1-65535", scan_type="syn")