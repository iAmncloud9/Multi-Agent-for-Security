import json
from typing import Dict, Any, List
from colorama import Fore, Style
from datetime import datetime

def format_results(results: Dict[str, Any], scan_type: int) -> str:
    """Format scan results for display"""
    if not results or results.get('status') == 'error':
        return f"{Fore.RED}❌ Scan failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}"
    
    if scan_type == 1:  # Port scan
        return format_port_scan_results(results)
    elif scan_type == 2:  # Subdomain scan
        return format_subdomain_scan_results(results)
    else:
        return json.dumps(results, indent=2)

# Format results from port scan server
def format_port_scan_results(results: Dict[str, Any]) -> str:
    """Format port scan results"""
    output = []
    
    # Header
    target = results.get('target', 'Unknown')
    scan_time = results.get('timestamp', 'Unknown')
    scan_type = results.get('raw_results', {}).get('scan_type', 'tcp')
    port_range = results.get('raw_results', {}).get('port_range', 'Unknown')
    
    output.append(f"{Fore.CYAN}🔍 Port Scan Results for {target}{Style.RESET_ALL}")
    output.append(f"{Fore.YELLOW}📅 Scan Time: {scan_time}{Style.RESET_ALL}")
    output.append(f"{Fore.YELLOW}🔍 Scan Type: {scan_type.upper()}{Style.RESET_ALL}")
    output.append(f"{Fore.YELLOW}🔢 Port Range: {port_range}{Style.RESET_ALL}")
    output.append("=" * 60)
    
    # Raw results
    raw_results = results.get('raw_results', {})
    if 'results' in raw_results:
        scan_data = raw_results['results']
        
        # Host info
        host_info = scan_data.get('host_info', {})
        output.append(f"\n{Fore.GREEN}🖥️  Host Information:{Style.RESET_ALL}")
        output.append(f"   IP Address: {host_info.get('ip', 'N/A')}")
        output.append(f"   Hostname: {host_info.get('hostname', 'N/A')}")
        output.append(f"   State: {host_info.get('state', 'N/A')}")
        
        # Summary
        summary = scan_data.get('summary', {})
        output.append(f"\n{Fore.GREEN}📊 Summary:{Style.RESET_ALL}")
        output.append(f"   Open Ports: {Fore.GREEN}{summary.get('total_open', 0)}{Style.RESET_ALL}")
        output.append(f"   Closed Ports: {summary.get('total_closed', 0)}")
        output.append(f"   Filtered Ports: {summary.get('total_filtered', 0)}")
        
        # Open ports details
        open_ports = scan_data.get('open_ports', [])
        if open_ports:
            output.append(f"\n{Fore.GREEN}🔓 Open Ports:{Style.RESET_ALL}")
            for port in open_ports:
                service_info = f"{port['service']}"
                if port.get('version'):
                    service_info += f" {port['version']}"
                if port.get('product'):
                    service_info += f" ({port['product']})"
                
                output.append(f"   {Fore.RED}{port['port']}/{port['protocol']}{Style.RESET_ALL} - {service_info}")
    
    # AI Analysis
    ai_analysis = results.get('ai_analysis', '')
    if ai_analysis:
        output.append(f"\n{Fore.CYAN}🤖 AI Security Analysis:{Style.RESET_ALL}")
        output.append(f"{ai_analysis}")

    return "\n".join(output)

# Format results from subdomain scan server
def format_subdomain_scan_results(results: Dict[str, Any]) -> str:
    """Format subdomain scan results"""
    output = []
    
    # Header
    target = results.get('target', 'Unknown')
    scan_time = results.get('timestamp', 'Unknown')
    output.append(f"{Fore.CYAN}🔍 Subdomain Scan Results for {target}{Style.RESET_ALL}")
    output.append(f"{Fore.YELLOW}📅 Scan Time: {scan_time}{Style.RESET_ALL}")
    output.append("=" * 60)
    
    # Raw results
    raw_results = results.get('raw_results', {})
    subdomains = raw_results.get('subdomains', [])
    
    # Summary
    output.append(f"\n{Fore.GREEN}📊 Summary:{Style.RESET_ALL}")
    output.append(f"   Total Subdomains Found: {Fore.GREEN}{len(subdomains)}{Style.RESET_ALL}")
    
    # Subdomains details
    if subdomains:
        output.append(f"\n{Fore.GREEN}🌐 Discovered Subdomains:{Style.RESET_ALL}")
        for subdomain in subdomains:
            output.append(f"   {Fore.YELLOW}{subdomain}{Style.RESET_ALL}")
    else:
        output.append(f"\n{Fore.YELLOW}⚠️ No subdomains discovered for this target{Style.RESET_ALL}")
    
    # AI Analysis
    ai_analysis = results.get('ai_analysis', '')
    if ai_analysis:
        output.append(f"\n{Fore.CYAN}🤖 AI Security Analysis:{Style.RESET_ALL}")
        output.append(f"{ai_analysis}")
    
    # Don't forget to return the joined output
    return "\n".join(output)