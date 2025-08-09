from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from langchain_ollama import OllamaLLM
from langchain.schema import BaseMessage, HumanMessage
import json
import logging

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
            return response
        except Exception as e:
            self.logger.error(f"Error generating response: {e}")
            return ""
    
    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse JSON response from LLM"""
        try:
            # Find JSON content between first { and last }
            start_idx = response.find('{')
            end_idx = response.rfind('}')
            
            if start_idx != -1 and end_idx != -1:
                json_str = response[start_idx:end_idx + 1]
                return json.loads(json_str)
            return None
        except (json.JSONDecodeError, ValueError) as e:
            self.logger.error(f"Error parsing JSON response: {e}")
            return None