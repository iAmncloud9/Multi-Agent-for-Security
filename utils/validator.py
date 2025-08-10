import re
import socket
from urllib.parse import urlparse
from typing import Union

def validate_ip(ip_address: str) -> bool:
    """Validate IPv4 address"""
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        return False

def validate_ipv6(ip_address: str) -> bool:
    """Validate IPv6 address"""
    try:
        socket.inet_pton(socket.AF_INET6, ip_address)
        return True
    except socket.error:
        return False

def validate_domain(domain: str) -> bool:
    """Validate domain name or URL"""
    # Clean input
    domain = domain.strip().lower()
    
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        domain = parsed.netloc
    
    # Remove www prefix
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Domain regex pattern
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    return bool(domain_pattern.match(domain)) and len(domain) <= 253

def validate_port_range(port_range: str) -> bool:
    """Validate port range format"""
    try:
        if '-' in port_range:
            start, end = port_range.split('-')
            start, end = int(start), int(end)
            return 1 <= start <= end <= 65535
        else:
            # Single port or comma-separated ports
            ports = port_range.split(',')
            for port in ports:
                port = int(port.strip())
                if not (1 <= port <= 65535):
                    return False
            return True
    except ValueError:
        return False

def validate_host(hostname: str) -> bool:
        """Validate if hostname is resolvable"""
        try:
            socket.gethostbyname(hostname)
            return True
        except socket.error:
            return False

def sanitize_input(user_input: str) -> str:
    """Sanitize user input to prevent injection attacks"""
    # Remove dangerous characters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'"]
    sanitized = user_input
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized.strip()