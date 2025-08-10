import logging
import json
from typing import Dict, Any
from src.agents.management_agent import ManagementAgent
# from src.agents.analysis_assessment_recommendation_agent import AnalysisAssessmentRecommendationAgent
from src.agents.tool_execution_agent import ToolExecutionAgent
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
        self.tool_agent = ToolExecutionAgent(model_name)
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

    # ======================================= TEST MANAGEMENT AGENT & TOOL EXECUTION AGENT ===================================================

    def test_management_and_tool_agents(self, user_input: str) -> Dict:
        """
        Test the integration between Management Agent and Tool Execution Agent
        """
        self.logger.info(f"Testing integrated agent workflow for: {user_input}")
        
        test_results = {
            "user_input": user_input,
            "management_analysis": None,
            "tool_execution_results": [],
            "final_status": "unknown",
            "execution_flow": []
        }
        
        try:
            # Step 1: Management Agent Analysis
            print("🔍 Step 1: Management Agent analyzing request...")
            execution_plan = self.management_agent._create_execution_plan(user_input)
            
            if not execution_plan:
                test_results["final_status"] = "failed"
                test_results["error"] = "Management Agent failed to create execution plan"
                return test_results
            
            test_results["management_analysis"] = execution_plan
            test_results["execution_flow"].append("Management Agent: Analysis completed")
            
            # Step 2: Check if Tool Execution is needed
            subtasks = execution_plan.get("subtasks", [])
            tool_execution_needed = False
            
            for subtask in subtasks:
                if subtask.get("agent") == "Tool_Execution_Agent":
                    tool_execution_needed = True
                    break
            
            if not tool_execution_needed:
                test_results["final_status"] = "completed"
                test_results["message"] = "No tool execution required for this request"
                test_results["execution_flow"].append("Management Agent: No tool execution needed")
                return test_results
            
            # Step 3: Execute Tool Tasks
            print("🔧 Step 2: Executing tool tasks...")
            for i, subtask in enumerate(subtasks):
                if subtask.get("agent") == "Tool_Execution_Agent":
                    print(f"   📋 Executing subtask {i+1}: {subtask.get('task', 'Unknown task')}")
                    
                    # Execute the tool task
                    tool_result = self.tool_agent.execute({
                        "task": subtask.get("task", ""),
                        "input_data": subtask.get("input_data", "")
                    })
                    
                    test_results["tool_execution_results"].append({
                        "subtask_index": i+1,
                        "task": subtask.get("task", ""),
                        "agent": subtask.get("agent", ""),
                        "result": tool_result
                    })
                    
                    test_results["execution_flow"].append(f"Tool Execution Agent: Subtask {i+1} completed")
            
            # Step 4: Determine final status
            all_successful = True
            for result in test_results["tool_execution_results"]:
                if result["result"].get("status") != "success":
                    all_successful = False
                    break
            
            test_results["final_status"] = "success" if all_successful else "partial_success"
            test_results["execution_flow"].append("Integration test: Completed")
            
            return test_results
            
        except Exception as e:
            self.logger.error(f"Error in integrated agent testing: {e}")
            test_results["final_status"] = "failed"
            test_results["error"] = str(e)
            test_results["execution_flow"].append(f"Error occurred: {str(e)}")
            return test_results
        

    def run_integrated_test_mode(self):
        """Run the system in integrated test mode"""
        print("=== Integrated Agent Testing Mode ===")
        
        while True:
            user_input = input("\nUser: ").strip()
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            
            if not user_input:
                continue
            
            print("\n" + "="*60)
            print("🚀 Starting Integrated Agent Test Workflow")
            print("="*60)
            
            result = self.test_management_and_tool_agents(user_input)
            
            print("\n=== Integrated Test Results ===")
            self._display_integrated_test_results(result)

    def _display_integrated_test_results(self, result: Dict):
        """Display integrated test results in a formatted way"""
        print(f"📝 User Input: {result.get('user_input', 'Unknown')}")
        print(f"🎯 Final Status: {result.get('final_status', 'Unknown').upper()}")
        
        # Display execution flow
        execution_flow = result.get('execution_flow', [])
        if execution_flow:
            print(f"\n🔄 Execution Flow:")
            for i, step in enumerate(execution_flow, 1):
                print(f"   {i}. {step}")
        
        # Display management analysis
        management_analysis = result.get('management_analysis')
        if management_analysis:
            print(f"\n🧠 Management Agent Analysis:")
            print(f"   Analysis: {management_analysis.get('analysis', 'N/A')}")
            
            subtasks = management_analysis.get('subtasks', [])
            if subtasks:
                print(f"   Planned Subtasks ({len(subtasks)}):")
                for i, subtask in enumerate(subtasks, 1):
                    agent = subtask.get('agent', 'Unknown')
                    task = subtask.get('task', 'Unknown')
                    print(f"      {i}. {agent}: {task}")
        
        # Display tool execution results
        tool_results = result.get('tool_execution_results', [])
        if tool_results:
            print(f"\n🔧 Tool Execution Results:")
            for tool_result in tool_results:
                subtask_idx = tool_result.get('subtask_index', 'N/A')
                task = tool_result.get('task', 'Unknown')
                agent = tool_result.get('agent', 'Unknown')
                execution_result = tool_result.get('result', {})
                
                print(f"\n   📋 Subtask {subtask_idx} ({agent}):")
                print(f"      Task: {task}")
                print(f"      Status: {execution_result.get('status', 'Unknown').upper()}")
                
                if execution_result.get('status') == 'success':
                    tool_used = execution_result.get('tool_used', 'Unknown')
                    print(f"      Tool Used: {tool_used}")
                    
                    # Display tool-specific results
                    tool_exec_result = execution_result.get('result', {})
                    if tool_exec_result.get('status') == 'success':
                        print(f"      ✅ Tool Execution: SUCCESS")
                        
                        if tool_used == 'nmap':
                            self._display_nmap_summary(tool_exec_result)
                        elif tool_used == 'subfinder':
                            self._display_subfinder_summary(tool_exec_result)
                    else:
                        print(f"      ❌ Tool Execution: FAILED")
                        print(f"      Error: {tool_exec_result.get('message', 'Unknown error')}")
                
                elif execution_result.get('status') == 'error':
                    print(f"      ❌ Agent Execution: FAILED")
                    print(f"      Error: {execution_result.get('message', 'Unknown error')}")
        
        # Display errors if any
        if result.get('error'):
            print(f"\n❌ Error: {result['error']}")
        
        # Display final summary
        print(f"\n📊 Test Summary:")
        if result.get('final_status') == 'success':
            print(f"   ✅ All components executed successfully")
            print(f"   ✅ Management Agent → Tool Execution integration working")
        elif result.get('final_status') == 'partial_success':
            print(f"   ⚠️  Some components executed successfully, others failed")
        elif result.get('final_status') == 'failed':
            print(f"   ❌ Test failed - check errors above")
        
        print("\n" + "="*60)

    def _display_nmap_summary(self, nmap_result: Dict):
        """Display brief Nmap results summary"""
        results = nmap_result.get('results', {})
        summary = results.get('summary', {})
        if summary:
            print(f"         📊 Nmap Results: {summary.get('total_open', 0)} open ports")
            
            open_ports = results.get('open_ports', [])
            if open_ports:
                port_list = [f"{port.get('port')}/{port.get('protocol')}" for port in open_ports[:3]]
                port_display = ", ".join(port_list)
                if len(open_ports) > 3:
                    port_display += f" (+{len(open_ports)-3} more)"
                print(f"         🔓 Key Ports: {port_display}")

    def _display_subfinder_summary(self, subfinder_result: Dict):
        """Display brief Subfinder results summary"""
        count = subfinder_result.get('count', 0)
        domain = subfinder_result.get('domain', 'Unknown')
        print(f"         🌐 Subfinder Results: {count} subdomains found for {domain}")
        
        subdomains = subfinder_result.get('subdomains', [])
        if subdomains:
            sample_domains = subdomains[:3]
            domain_display = ", ".join(sample_domains)
            if len(subdomains) > 3:
                domain_display += f" (+{len(subdomains)-3} more)"
            print(f"         📋 Sample: {domain_display}")

    # =========================================================================================================================

def main():
    """Main function"""
    try:
        # Initialize the system
        system = MultiAgentSecuritySystem()
        
        # Run test mode - Management Agent
        #system.run_management_test_mode()

        # Run test mode - Management Agent & Tool Execution Agent
        system.run_integrated_test_mode()

        # Run interactive mode
        #system.run_interactive()
        
    except KeyboardInterrupt:
        print("\nSystem interrupted by user")
    except Exception as e:
        print(f"System error: {e}")

if __name__ == "__main__":
    main()