from typing import Dict, Any, List
from .base_agent import BaseAgent
from utils.agent_prompt import AgentPrompts
import json
import logging

class ManagementAgent(BaseAgent):
    """Central management agent that coordinates other agents"""
    
    def __init__(self, model_name: str = "llama3.2"):
        super().__init__(model_name, "ManagementAgent")
        self.sub_agents = {}
        
    def register_sub_agent(self, agent_name: str, agent_instance):
        """Register a sub-agent with the management agent"""
        self.sub_agents[agent_name] = agent_instance
        self.logger.info(f"Registered sub-agent: {agent_name}")
    
    def execute(self, user_input: str) -> Dict[str, Any]:
        """
        Main execution method for the management agent
        1. Analyze user request
        2. Create execution plan
        3. Execute subtasks with appropriate agents
        4. Synthesize results
        """
        try:
            # Step 1: Analyze and create execution plan
            execution_plan = self._create_execution_plan(user_input)
            if not execution_plan:
                return {"error": "Failed to create execution plan"}
            
            # Step 2: Execute subtasks
            subtask_results = []
            for subtask in execution_plan.get("subtasks", []):
                result = self._execute_subtask(subtask)
                subtask_results.append({
                    "task": subtask.get("task"),
                    "agent": subtask.get("agent"),
                    "result": result
                })
            
            # Step 3: Synthesize final result
            final_result = self._synthesize_results(
                user_input, 
                execution_plan, 
                subtask_results
            )
            
            return final_result
            
        except Exception as e:
            self.logger.error(f"Error in management agent execution: {e}")
            return {"error": f"Management agent execution failed: {str(e)}"}
    
    def _create_execution_plan(self, user_input: str) -> Dict[str, Any]:
        """Create execution plan based on user input"""
        prompt = AgentPrompts.MANAGEMENT_AGENT_PROMPT.format(
            user_input=user_input
        )
        
        response = self._generate_response(prompt)
        execution_plan = self._parse_json_response(response)
        
        if execution_plan:
            self.logger.info(f"Created execution plan: {execution_plan}")
            return execution_plan
        else:
            self.logger.error("Failed to parse execution plan")
            return {}
    
    def _execute_subtask(self, subtask: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single subtask using the appropriate agent"""
        agent_name = subtask.get("agent")
        task = subtask.get("task")
        input_data = subtask.get("input_data")
        
        if agent_name not in self.sub_agents:
            return {"error": f"Agent {agent_name} not found"}
        
        try:
            agent = self.sub_agents[agent_name]
            result = agent.execute({
                "task": task,
                "input_data": input_data
            })
            return result
        except Exception as e:
            self.logger.error(f"Error executing subtask with {agent_name}: {e}")
            return {"error": f"Subtask execution failed: {str(e)}"}
    
    def _synthesize_results(self, user_input: str, execution_plan: Dict[str, Any], 
                          subtask_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Synthesize final results from all subtask results"""
        return {
            "user_request": user_input,
            "execution_analysis": execution_plan.get("analysis", ""),
            "subtask_results": subtask_results,
            "summary": self._generate_summary(subtask_results),
            "status": "completed"
        }
    
    def _generate_summary(self, results: List[Dict[str, Any]]) -> str:
        """Generate a summary of all results"""
        summary_parts = []
        for result in results:
            if result.get("result") and not result["result"].get("error"):
                summary_parts.append(f"- {result['task']}: Completed successfully")
            else:
                summary_parts.append(f"- {result['task']}: Failed or had issues")
        
        return "\n".join(summary_parts)