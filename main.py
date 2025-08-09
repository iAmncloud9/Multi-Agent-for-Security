import logging
import json
from typing import Dict, Any
from src.agents.management_agent import ManagementAgent
# from src.agents.analysis_assessment_recommendation_agent import AnalysisAssessmentRecommendationAgent
# from src.agents.tool_execution_agent import ToolExecutionAgent
# from src.agents.report_agent import ReportAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class MultiAgentSecuritySystem:
    """Main class for the Multi-Agent Security System"""
    
    def __init__(self, model_name: str = "llama3.2"):
        self.logger = logging.getLogger("MultiAgentSecuritySystem")
        
        # Initialize Management Agent
        self.management_agent = ManagementAgent(model_name)
        
        # Initialize Sub-Agents
        self.analysis_agent = None
        self.tool_agent = None
        self.report_agent = None
        
        # Register sub-agents with management agent
        self._register_agents()
        
        self.logger.info("Multi-Agent Security System initialized successfully")
    
    def _register_agents(self):
        """Register all sub-agents with the management agent"""
        self.management_agent.register_sub_agent(
            "Analysis_Assessment_Recommendation_Agent", 
            self.analysis_agent
        )
        self.management_agent.register_sub_agent(
            "Tool_Execution_Agent", 
            self.tool_agent
        )
        self.management_agent.register_sub_agent(
            "Report_Agent", 
            self.report_agent
        )
    
    def process_request(self, user_input: str) -> Dict:
        """
        Process user request through the multi-agent system
        """
        self.logger.info(f"Processing user request: {user_input}")
        
        try:
            # Execute through management agent
            result = self.management_agent.execute(user_input)
            
            self.logger.info("Request processed successfully")
            return result
            
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return {
                "error": f"System error: {str(e)}",
                "status": "failed"
            }
    
    def run_interactive(self):
        """Run the system in interactive mode"""
        print("=== Multi-Agent Security System ===")
        print("Enter your security requests (type 'quit' to exit)")
        
        while True:
            user_input = input("\nUser: ").strip()
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            
            if not user_input:
                continue
            
            print("Processing...")
            result = self.process_request(user_input)
            
            print("\n=== System Response ===")
            print(json.dumps(result, indent=2, ensure_ascii=False))

    # =========================== TEST MANAGEMENT AGENT ===========================
    def test_management_agent_only(self, user_input: str) -> Dict:
            """
            Test only the Management Agent analysis without executing sub-agents
            """
            self.logger.info(f"Testing Management Agent analysis for: {user_input}")
            
            try:
                # Only test the analysis part of ManagementAgent
                execution_plan = self.management_agent._create_execution_plan(user_input)
                
                if not execution_plan:
                    return {
                        "error": "Management Agent failed to create execution plan",
                        "status": "failed"
                    }
                
                return {
                    "status": "success",
                    "agent": "ManagementAgent",
                    "user_request": user_input,
                    "analysis_result": execution_plan,
                    "message": "Management Agent analysis completed successfully"
                }
                
            except Exception as e:
                self.logger.error(f"Error in Management Agent testing: {e}")
                return {
                    "error": f"Management Agent error: {str(e)}",
                    "status": "failed"
                }

    def run_management_test_mode(self):
            """Run the system in Management Agent test mode"""
            print("=== Management Agent Testing Mode ===")
            print("This mode will only test the Management Agent's analysis capability")
            print("Enter your security requests (type 'quit' to exit, 'full' to switch to full mode)")
            
            while True:
                user_input = input("\nUser: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("Goodbye!")
                    break
                
                if user_input.lower() == 'full':
                    print("Switching to full system mode...")
                    self._register_agents()
                    self.run_interactive()
                    break
                
                if not user_input:
                    continue
                
                print("Analyzing with Management Agent...")
                result = self.test_management_agent_only(user_input)
                
                print("\n=== Management Agent Analysis Result ===")
                self._display_management_analysis(result)


    def _display_management_analysis(self, result: Dict):
            """Display Management Agent analysis in a formatted way"""
            if result.get("status") == "failed":
                print(f"❌ Error: {result.get('error', 'Unknown error')}")
                return
            
            analysis_result = result.get("analysis_result", {})
            
            print(f"✅ Status: {result.get('status', 'Unknown')}")
            print(f"🤖 Agent: {result.get('agent', 'Unknown')}")
            print(f"📝 User Request: {result.get('user_request', 'Unknown')}")
            
            # Display analysis
            if "analysis" in analysis_result:
                print(f"\n📊 Analysis:")
                print(f"   {analysis_result['analysis']}")
            
            # Display subtasks
            if "subtasks" in analysis_result and analysis_result["subtasks"]:
                print(f"\n📋 Planned Subtasks ({len(analysis_result['subtasks'])}):")
                for i, subtask in enumerate(analysis_result["subtasks"], 1):
                    print(f"   {i}. Task: {subtask.get('task', 'Unknown')}")
                    print(f"      Agent: {subtask.get('agent', 'Unknown')}")
                    # Safe handling of input_data
                input_data = subtask.get('input_data', 'No data')
                if input_data is None:
                    input_data = 'No data'
                elif not isinstance(input_data, str):
                    input_data = str(input_data)
                
                # Safely truncate the input data
                if len(input_data) > 100:
                    print(f"      Input: {input_data[:100]}...")
                else:
                    print(f"      Input: {input_data}")
                    print()
            
            # Display raw JSON for debugging
            print("\n🔧 Raw JSON Response:")
            print(json.dumps(analysis_result, indent=2, ensure_ascii=False))

    # =============================================================================

def main():
    """Main function"""
    try:
        # Initialize the system
        system = MultiAgentSecuritySystem()
        
        # Run test mode - Management Agent
        system.run_management_test_mode()

        # Run interactive mode
        #system.run_interactive()
        
    except KeyboardInterrupt:
        print("\nSystem interrupted by user")
    except Exception as e:
        print(f"System error: {e}")

if __name__ == "__main__":
    main()