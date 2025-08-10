from typing import Dict, Any
from .base_agent import BaseAgent
from utils.agent_prompt import AgentPrompts
import logging
import json
import re
# Import Tools
from src.tools.nmap_tool import NmapTool
from src.tools.subfinder_tool import SubfinderTool

class ToolExecutionAgent(BaseAgent):
    """Agent responsible for executing security tools"""
    
    def __init__(self, model_name: str = "llama3.2"):
        super().__init__(model_name, "ToolExecutionAgent")
        self.available_tools = {}
        self._initialize_tools()
    
    def _initialize_tools(self):
        """Initialize available security tools"""
        try:
            # Initialize tool instances
            self.available_tools = {
                'nmap': NmapTool(),
                'subfinder': SubfinderTool()
            }
            
            self.logger.info(f"Initialized tools: {list(self.available_tools.keys())}")
            
        except Exception as e:
            self.logger.error(f"Error initializing tools: {e}")
            self.available_tools = {}
    
    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute security tools based on the task requirements
        """
        try:
            task = input_data.get('task', '')
            task_input = input_data.get('input_data', '')
            
            self.logger.info(f"Executing task: {task}")
            self.logger.info(f"Input data type: {type(task_input)}, value: {task_input}")
            
            # Convert input_data to string if it's not already
            task_input_str = self._normalize_input_data(task_input)
            
            # Analyze task to determine which tool to use
            tool_analysis = self._analyze_tool_requirement(task, task_input_str)
            
            if tool_analysis.get('error'):
                return {
                    "status": "error",
                    "message": tool_analysis['error'],
                    "tool_used": "none"
                }
            
            # Execute the appropriate tool
            tool_name = tool_analysis.get('tool')
            tool_params = tool_analysis.get('parameters', {})
            
            if tool_name not in self.available_tools:
                return {
                    "status": "error",
                    "message": f"Tool {tool_name} not available",
                    "available_tools": list(self.available_tools.keys())
                }
            
            # Execute the tool
            result = self._execute_tool(tool_name, tool_params)
            
            return {
                "status": "success",
                "tool_used": tool_name,
                "task": task,
                "result": result,
                "execution_details": {
                    "parameters_used": tool_params,
                    "tool_analysis": tool_analysis.get('rationale', ''),
                    "original_input": task_input_str
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error in tool execution: {e}")
            return {
                "status": "error",
                "message": f"Tool execution failed: {str(e)}"
            }
    
    def _normalize_input_data(self, input_data: Any) -> str:
        """Normalize input_data to string format for processing"""
        try:
            if isinstance(input_data, str):
                return input_data
            elif isinstance(input_data, dict):
                # Convert dict to string format
                if 'domain' in input_data:
                    domain = input_data['domain']
                    # Clean domain from URL format
                    if domain.startswith(('http://', 'https://')):
                        from urllib.parse import urlparse
                        parsed = urlparse(domain)
                        domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
                    return f"domain: {domain}"
                elif 'target' in input_data:
                    target = input_data['target']
                    port_range = input_data.get('port_range', '1-1000')
                    scan_type = input_data.get('scan_type', 'tcp')
                    return f"target: {target} port_range: {port_range} scan_type: {scan_type}"
                else:
                    # Try to convert dict to key: value format
                    parts = []
                    for key, value in input_data.items():
                        parts.append(f"{key}: {value}")
                    return " ".join(parts)
            else:
                return str(input_data)
        except Exception as e:
            self.logger.error(f"Error normalizing input data: {e}")
            return str(input_data)

    def _analyze_tool_requirement(self, task: str, input_data: str) -> Dict[str, Any]:
        """
        Analyze the task to determine which tool to use and with what parameters
        """
        task_lower = task.lower()
        input_lower = input_data.lower()
        
        # Port scanning detection
        if any(keyword in task_lower for keyword in ['port scan', 'nmap', 'port', 'scan ports']):
            return self._analyze_nmap_requirement(task, input_data)
        
        # Subdomain discovery detection
        elif any(keyword in task_lower for keyword in ['subdomain', 'subfinder', 'domain discovery']):
            return self._analyze_subfinder_requirement(task, input_data)
        
        # Default case - try to infer from input data
        elif any(keyword in input_lower for keyword in ['ip:', 'target ip', 'scan']):
            return self._analyze_nmap_requirement(task, input_data)
        
        elif any(keyword in input_lower for keyword in ['domain:', 'target domain']):
            return self._analyze_subfinder_requirement(task, input_data)
        
        else:
            return {
                'error': f"Cannot determine appropriate tool for task: {task}",
                'available_tools': list(self.available_tools.keys())
            }
    
    def _analyze_nmap_requirement(self, task: str, input_data: str) -> Dict[str, Any]:
        """Analyze requirements for Nmap tool"""
        # Extract target IP/host
        target = None
        
        # Look for IP patterns
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_match = re.search(ip_pattern, input_data)
        if ip_match:
            target = ip_match.group()
        
        # Look for explicit target specification
        target_patterns = [
            r'target[:\s]+([^\s,]+)',
            r'ip[:\s]+([^\s,]+)',
            r'host[:\s]+([^\s,]+)'
        ]
        
        for pattern in target_patterns:
            match = re.search(pattern, input_data, re.IGNORECASE)
            if match:
                target = match.group(1)
                break
        
        if not target:
            return {'error': 'No target IP/host specified for port scan'}
        
        # Extract port range (default to common ports)
        port_range = "1-1000"
        port_patterns = [
            r'port[s]?[:\s]+([0-9,-]+)',
            r'range[:\s]+([0-9,-]+)'
        ]
        
        for pattern in port_patterns:
            match = re.search(pattern, input_data, re.IGNORECASE)
            if match:
                port_range = match.group(1)
                break
        
        # Determine scan type
        scan_type = "tcp"
        if 'udp' in input_data.lower():
            scan_type = "udp"
        elif 'syn' in input_data.lower():
            scan_type = "syn"
        
        return {
            'tool': 'nmap',
            'parameters': {
                'target': target,
                'port_range': port_range,
                'scan_type': scan_type
            },
            'rationale': f"Port scanning requested for {target} using {scan_type.upper()} scan"
        }
    
    def _analyze_subfinder_requirement(self, task: str, input_data: str) -> Dict[str, Any]:
        """Analyze requirements for Subfinder tool"""
        # Extract target domain
        target = None
        
        # Look for domain patterns
        domain_patterns = [
            r'domain[:\s]+([^\s,]+)',
            r'target[:\s]+([^\s,]+)',
            r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        ]
        
        for pattern in domain_patterns:
            match = re.search(pattern, input_data, re.IGNORECASE)
            if match:
                target = match.group(1) if 'domain' in pattern else match.group()
                break
        
        if not target:
            return {'error': 'No target domain specified for subdomain discovery'}
        
        # Extract options
        options = {}
        
        if 'recursive' in input_data.lower():
            options['recursive'] = True
        
        # Look for timeout
        timeout_match = re.search(r'timeout[:\s]+(\d+)', input_data, re.IGNORECASE)
        if timeout_match:
            options['timeout'] = int(timeout_match.group(1))
        
        return {
            'tool': 'subfinder',
            'parameters': {
                'domain': target,
                'options': options if options else None
            },
            'rationale': f"Subdomain discovery requested for domain {target}"
        }
    
    def _execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the specified tool with given parameters"""
        try:
            tool = self.available_tools[tool_name]
            
            if tool_name == 'nmap':
                result = tool.scan_ports(
                    target=parameters['target'],
                    port_range=parameters.get('port_range', '1-1000'),
                    scan_type=parameters.get('scan_type', 'tcp')
                )
                
            elif tool_name == 'subfinder':
                result = tool.find_subdomains(
                    domain=parameters['domain'],
                    options=parameters.get('options')
                )
            
            else:
                return {"error": f"Unknown tool: {tool_name}"}
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing {tool_name}: {e}")
            return {
                "error": f"Tool execution error: {str(e)}",
                "tool": tool_name
            }