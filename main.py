import logging
import json
from typing import Dict, Any
from datetime import datetime
from src.agents.management_agent import ManagementAgent
from src.agents.analysis_assessment_recommendation_agent import AnalysisAssessmentRecommendationAgent
from src.agents.tool_execution_agent import ToolExecutionAgent
from src.agents.report_agent import ReportAgent

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
        self.analysis_agent = AnalysisAssessmentRecommendationAgent(model_name)
        self.tool_agent = ToolExecutionAgent(model_name)
        self.report_agent = ReportAgent(model_name)
        
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

    # ======================================= TEST MANAGEMENT AGENT & TOOL EXECUTION AGENT & ANALYSIS AGENT & REPORT AGENT =======================================

    def test_integrated_agents(self, user_input: str) -> Dict:
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
            successful_tool_results = []

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

                    # Collect successful tool results for analysis
                    if tool_result.get("status") == "success":
                        successful_tool_results.append({
                            "subtask_index": i+1,
                            "task": subtask.get("task", ""),
                            "result": tool_result
                        })
                    
                    test_results["execution_flow"].append(f"Tool Execution Agent: Subtask {i+1} completed")
            
            # Step 4: Analysis Assessment Recommendation
            if successful_tool_results:
                print("📊 Step 3: Performing security analysis and assessment...")
                
                for tool_data in successful_tool_results:
                    tool_result = tool_data["result"]
                    subtask_index = tool_data["subtask_index"]
                    
                    # Create analysis task based on tool used
                    tool_used = tool_result.get('tool_used', 'security tool')
                    analysis_task = f"Analyze security findings from {tool_used} scan and provide risk assessment with recommendations"
                    
                    print(f"   🔍 Analyzing results from subtask {subtask_index} ({tool_used})...")
                    
                    # Execute analysis agent
                    analysis_result = self.analysis_agent.execute({
                        "task": analysis_task,
                        "input_data": tool_result
                    })
                    
                    test_results["analysis_results"].append({
                        "subtask_index": subtask_index,
                        "tool_used": tool_used,
                        "analysis_task": analysis_task,
                        "result": analysis_result
                    })
                    
                    test_results["execution_flow"].append(f"Analysis Agent: Subtask {subtask_index} analyzed")
            else:
                test_results["execution_flow"].append("Analysis Agent: No successful tool results to analyze")
            
            # Step 5: Report Generation
            print("📝 Step 4: Generating comprehensive security report...")
            
            # Prepare consolidated data for report generation
            consolidated_data = {
                "user_request": user_input,
                "execution_plan": execution_plan,
                "tool_results": test_results["tool_execution_results"],
                "analysis_results": test_results["analysis_results"],
                "assessment_scope": f"Multi-Agent Security Assessment for: {user_input}",
                "timestamp": self._get_current_timestamp()
            }
            
            # Generate report
            report_task = "Generate comprehensive security assessment report consolidating all findings, analysis, and recommendations"
            report_result = self.report_agent.execute({
                "task": report_task,
                "input_data": consolidated_data
            })
            
            test_results["report_result"] = report_result
            test_results["execution_flow"].append("Report Agent: Comprehensive report generated")
            
            # Step 6: Determine final status
            tool_success = any(result["result"].get("status") == "success" 
                            for result in test_results["tool_execution_results"])
            
            analysis_success = any(result["result"].get("status") == "success" 
                                for result in test_results.get("analysis_results", []))
            
            report_success = report_result.get("status") == "success"
            
            if tool_success and analysis_success and report_success:
                test_results["final_status"] = "success"
            elif tool_success and analysis_success:
                test_results["final_status"] = "partial_success"
            elif tool_success:
                test_results["final_status"] = "minimal_success"
            else:
                test_results["final_status"] = "failed"
            
            test_results["execution_flow"].append("Full integration test: Completed")
            
            return test_results
        
        except Exception as e:
            self.logger.error(f"Error in full integrated agent testing: {e}")
            test_results["final_status"] = "failed"
            test_results["error"] = str(e)
            test_results["execution_flow"].append(f"Error occurred: {str(e)}")
            return test_results
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp for report generation"""
        return datetime.now().isoformat()
        

    def run_integrated_test_mode(self):
        """Run the system in integrated test mode"""
        print("=== Full Integrated Agent Testing Mode ===")
        print("Testing: Management Agent → Tool Execution Agent → Analysis Agent")
        print("Enter your security requests (type 'quit' to exit)")
        
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

            result = self.test_integrated_agents(user_input)

            print("\n=== Integrated Test Results ===")
            self._display_integrated_test_results(result)

    def _display_integrated_test_results(self, result: Dict):
        """Run the system in integrated test mode"""
        print("=== Full Integrated Agent Testing Mode ===")
        print("Testing: Management Agent → Tool Execution Agent → Analysis Agent")
        print("Enter your security requests (type 'quit' to exit)")
        
        while True:
            user_input = input("\nUser: ").strip()
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            
            if not user_input:
                continue
            
            print("\n" + "="*70)
            print("🚀 Starting Full Integrated Agent Test Workflow")
            print("="*70)
            
            result = self.test_integrated_agents(user_input)
            
            print("\n=== Full Integrated Test Results ===")
            self._display_full_integrated_test_results(result)

    def _display_full_integrated_test_results(self, result: Dict):
        """Display full integrated test results in a formatted way"""
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
        
        # Display analysis results
        analysis_results = result.get('analysis_results', [])
        if analysis_results:
            print(f"\n📊 Analysis Assessment Results:")
            for analysis in analysis_results:
                subtask_idx = analysis.get('subtask_index', 'N/A')
                tool_used = analysis.get('tool_used', 'Unknown')
                analysis_result = analysis.get('result', {})
                
                print(f"\n   🔍 Analysis for Subtask {subtask_idx} ({tool_used}):")
                print(f"      Status: {analysis_result.get('status', 'Unknown').upper()}")
                
                if analysis_result.get('status') == 'success':
                    analysis_data = analysis_result.get('analysis', {})
                    
                    # Display risk assessment
                    risk_assessment = analysis_data.get('risk_assessment', {})
                    if risk_assessment:
                        risk_level = risk_assessment.get('level', 'Unknown')
                        risk_score = risk_assessment.get('score', 'N/A')
                        print(f"      ⚠️  Risk Level: {risk_level} (Score: {risk_score}/10)")
                        
                        risk_factors = risk_assessment.get('factors', [])
                        if risk_factors:
                            factors_display = ', '.join(risk_factors[:2])
                            if len(risk_factors) > 2:
                                factors_display += f" (+{len(risk_factors)-2} more)"
                            print(f"      🎯 Key Risk Factors: {factors_display}")
                    
                    # Display recommendations count
                    recommendations = analysis_data.get('recommendations', [])
                    if recommendations:
                        print(f"      💡 Recommendations: {len(recommendations)} actions suggested")
                        
                        # Show top 2 recommendations
                        for i, rec in enumerate(recommendations[:2], 1):
                            priority = rec.get('priority', 'Unknown')
                            action = rec.get('action', 'Unknown action')
                            print(f"         {i}. [{priority}] {action[:50]}{'...' if len(action) > 50 else ''}")
                    
                    # Display brief analysis summary
                    analysis_text = analysis_data.get('analysis', '')
                    if analysis_text:
                        summary = analysis_text[:100] + '...' if len(analysis_text) > 100 else analysis_text
                        print(f"      📋 Summary: {summary}")
                
                elif analysis_result.get('status') == 'error':
                    print(f"      ❌ Analysis Failed: {analysis_result.get('message', 'Unknown error')}")
        
        # Display report results
        report_result = result.get('report_result')
        if report_result:
            print(f"\n📋 Security Assessment Report:")
            print(f"   Status: {report_result.get('status', 'Unknown').upper()}")
            
            if report_result.get('status') == 'success':
                report_data = report_result.get('report', {})
                
                # Display executive summary
                exec_summary = report_data.get('executive_summary', '')
                if exec_summary:
                    summary_preview = exec_summary[:200] + '...' if len(exec_summary) > 200 else exec_summary
                    print(f"   📄 Executive Summary: {summary_preview}")
                
                # Display report statistics
                report_stats = report_data.get('report_statistics', {})
                if report_stats:
                    findings_count = report_stats.get('total_findings', 0)
                    recommendations_count = report_stats.get('total_recommendations', 0)
                    print(f"   📊 Report Stats: {findings_count} findings, {recommendations_count} recommendations")
                
                # Display risk summary
                risk_summary = report_data.get('risk_summary', {})
                if risk_summary:
                    total_risks = risk_summary.get('total_risks', 0)
                    critical_risks = risk_summary.get('critical_risks', 0)
                    high_risks = risk_summary.get('high_risks', 0)
                    print(f"   ⚠️  Risk Summary: {total_risks} total risks ({critical_risks} critical, {high_risks} high)")
                
                # Display report metadata
                metadata = report_result.get('metadata', {})
                if metadata:
                    report_type = metadata.get('report_type', 'Unknown')
                    print(f"   📋 Report Type: {report_type}")
            
            elif report_result.get('status') == 'error':
                print(f"   ❌ Report Generation Failed: {report_result.get('message', 'Unknown error')}")
        
        # Display errors if any
        if result.get('error'):
            print(f"\n❌ Error: {result['error']}")
        
        # Display final summary
        print(f"\n📊 Full Integration Test Summary:")
        tool_count = len(result.get('tool_execution_results', []))
        analysis_count = len(result.get('analysis_results', []))
        report_status = "✅" if result.get('report_result', {}).get('status') == 'success' else "❌"
        
        if result.get('final_status') == 'success':
            print(f"   ✅ All components executed successfully")
            print(f"   ✅ Management Agent → Tool Execution ({tool_count}) → Analysis ({analysis_count}) → Report {report_status} integration working")
        elif result.get('final_status') == 'partial_success':
            print(f"   ⚠️  Tools and analysis executed successfully, but report had issues")
            print(f"   ⚠️  Tool Execution: {tool_count} tasks, Analysis: {analysis_count} results, Report: {report_status}")
        elif result.get('final_status') == 'minimal_success':
            print(f"   ⚠️  Tools executed successfully, but analysis and report had issues")
            print(f"   ⚠️  Tool Execution: {tool_count} tasks, Analysis: {analysis_count} results, Report: {report_status}")
        elif result.get('final_status') == 'failed':
            print(f"   ❌ Test failed - check errors above")
        
        print("\n" + "="*70)

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