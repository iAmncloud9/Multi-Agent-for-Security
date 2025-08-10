from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from langchain_ollama import OllamaLLM
import json
import logging
import re

class BaseAgent(ABC):
    """Base class for all agents in the system"""
    
    def __init__(self, model_name: str = "llama3.2", agent_name: str = "BaseAgent"):
        self.agent_name = agent_name
        self.model = OllamaLLM(model=model_name)
        self.logger = logging.getLogger(agent_name)
        
    @abstractmethod
    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the agent's main functionality"""
        pass
    
    def _generate_response(self, prompt: str) -> str:
        """Generate response using the LLM"""
        try:
            response = self.model.invoke(prompt)
            # Log full response for debugging
            self.logger.info(f"=== FULL LLM RESPONSE START ===")
            self.logger.info(response)
            self.logger.info(f"=== FULL LLM RESPONSE END ===")
            return response
        except Exception as e:
            self.logger.error(f"Error generating response: {e}")
            return ""
    
    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse JSON response from LLM with improved error handling"""
        if not response:
            self.logger.error("Empty response from LLM")
            return None
            
        self.logger.info(f"Attempting to parse response (length: {len(response)})")
        
        try:
            # Method 1: Clean and try direct parsing
            cleaned = self._clean_response_for_json(response)
            if cleaned:
                try:
                    result = json.loads(cleaned)
                    self.logger.info("✅ Successfully parsed JSON after cleaning")
                    return result
                except json.JSONDecodeError as e:
                    self.logger.error(f"JSON parse error after cleaning: {e}")
                    self.logger.error(f"Cleaned JSON: {cleaned}")
            
            # Method 2: Try to extract and fix JSON manually
            fixed_json = self._extract_and_fix_json(response)
            if fixed_json:
                try:
                    result = json.loads(fixed_json)
                    self.logger.info("✅ Successfully parsed JSON after manual fixing")
                    return result
                except json.JSONDecodeError as e:
                    self.logger.error(f"JSON parse error after manual fix: {e}")
                    self.logger.error(f"Fixed JSON attempt: {fixed_json}")
            
            # Method 3: Create fallback JSON
            self.logger.warning("All JSON parsing failed, creating fallback")
            return self._create_fallback_json(response)
            
        except Exception as e:
            self.logger.error(f"Unexpected error in JSON parsing: {e}")
            return None
    
    def _clean_response_for_json(self, response: str) -> Optional[str]:
        """Clean response to extract valid JSON"""
        try:
            # Remove markdown code blocks
            response = re.sub(r'```json\s*', '', response, flags=re.IGNORECASE)
            response = re.sub(r'```\s*', '', response)
            
            # Find JSON between braces
            start_idx = response.find('{')
            end_idx = response.rfind('}')
            
            if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
                json_part = response[start_idx:end_idx + 1]
                
                # Basic cleaning
                json_part = re.sub(r'\n\s*', ' ', json_part)  # Remove newlines and extra spaces
                json_part = re.sub(r',(\s*[}\]])', r'\1', json_part)  # Remove trailing commas
                
                return json_part.strip()
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in cleaning response: {e}")
            return None
    
    def _extract_and_fix_json(self, response: str) -> Optional[str]:
        """Extract and manually fix common JSON issues"""
        try:
            # Find all potential JSON objects
            json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
            matches = re.findall(json_pattern, response, re.DOTALL)
            
            for match in matches:
                # Try to fix common issues
                fixed = match
                
                # Fix unquoted keys
                fixed = re.sub(r'(\w+):', r'"\1":', fixed)
                
                # Fix single quotes to double quotes
                fixed = fixed.replace("'", '"')
                
                # Remove trailing commas
                fixed = re.sub(r',(\s*[}\]])', r'\1', fixed)
                
                # Fix multiple spaces
                fixed = re.sub(r'\s+', ' ', fixed)
                
                try:
                    # Test if this fixed version is valid
                    json.loads(fixed)
                    return fixed
                except json.JSONDecodeError:
                    continue
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in manual JSON fixing: {e}")
            return None
    
    def _create_fallback_json(self, response: str) -> Dict[str, Any]:
        """Create fallback JSON when parsing completely fails"""
        self.logger.warning("Creating fallback JSON structure")
        
        return {
            "analysis": "Failed to parse LLM response properly",
            "subtasks": [{
                "task": "Manual processing required",
                "agent": "Tool_Execution_Agent", 
                "input_data": "LLM response parsing failed",
                "rationale": "Fallback due to JSON parsing error"
            }],
            "parsing_error": True,
            "raw_response": response[:500] + "..." if len(response) > 500 else response
        }