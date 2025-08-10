from typing import Dict, Any, List
from .base_agent import BaseAgent
from utils.agent_prompt import AgentPrompts
import logging
import json
import re
from datetime import datetime

class ReportAgent(BaseAgent):
    """Agent specialized in generating comprehensive security reports"""
    
    def __init__(self, model_name: str = "llama3.2"):
        super().__init__(model_name, "ReportAgent")
        self.logger.info("Report Agent initialized")
    
    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute report generation based on consolidated security data
        """
        try:
            task = input_data.get('task', '')
            consolidated_data = input_data.get('input_data', {})
            
            self.logger.info(f"Generating report for task: {task}")
            self.logger.info(f"Consolidated data keys: {list(consolidated_data.keys()) if isinstance(consolidated_data, dict) else 'Not a dict'}")
            
            # Normalize input data for reporting
            processed_data = self._normalize_report_data(consolidated_data)
            
            if not processed_data:
                return {
                    "status": "error",
                    "message": "No valid data provided for report generation",
                    "agent": "ReportAgent"
                }
            
            # Generate comprehensive report
            report_result = self._generate_comprehensive_report(task, processed_data)
            
            if report_result.get('error'):
                return {
                    "status": "error",
                    "message": report_result['error'],
                    "agent": "ReportAgent"
                }
            
            # Structure the final result
            return {
                "status": "success",
                "agent": "ReportAgent",
                "task": task,
                "report": report_result,
                "metadata": {
                    "report_timestamp": self._get_timestamp(),
                    "report_type": self._determine_report_type(task),
                    "data_sources": self._identify_data_sources(processed_data)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error in report generation: {e}")
            return {
                "status": "error",
                "message": f"Report generation failed: {str(e)}",
                "agent": "ReportAgent"
            }
    
    def _normalize_report_data(self, data: Any) -> str:
        """Normalize various input data formats for report generation"""
        try:
            if isinstance(data, str):
                return data
            elif isinstance(data, dict):
                # Handle consolidated results from multiple agents
                formatted_parts = []
                
                # Add user request context
                if 'user_request' in data:
                    formatted_parts.append(f"Assessment Request: {data['user_request']}")
                
                # Add execution plan
                if 'execution_plan' in data:
                    plan = data['execution_plan']
                    formatted_parts.append(f"Execution Plan: {plan.get('analysis', 'N/A')}")
                
                # Add tool results
                if 'tool_results' in data:
                    tool_results = data['tool_results']
                    formatted_parts.append(f"Tool Execution Results: {len(tool_results)} tools executed")
                    for i, tool_result in enumerate(tool_results, 1):
                        task = tool_result.get('task', 'Unknown')
                        status = tool_result.get('result', {}).get('status', 'Unknown')
                        formatted_parts.append(f"  {i}. {task}: {status}")
                
                # Add analysis results
                if 'analysis_results' in data:
                    analysis_results = data['analysis_results']
                    formatted_parts.append(f"Security Analysis Results: {len(analysis_results)} analyses completed")
                    for i, analysis in enumerate(analysis_results, 1):
                        tool_used = analysis.get('tool_used', 'Unknown')
                        status = analysis.get('analysis_result', {}).get('status', 'Unknown')
                        formatted_parts.append(f"  {i}. {tool_used} Analysis: {status}")
                
                # Add assessment scope and timestamp
                if 'assessment_scope' in data:
                    formatted_parts.append(f"Assessment Scope: {data['assessment_scope']}")
                if 'timestamp' in data:
                    formatted_parts.append(f"Assessment Timestamp: {data['timestamp']}")
                
                return "\n".join(formatted_parts)
            else:
                return str(data)
                
        except Exception as e:
            self.logger.error(f"Error normalizing report data: {e}")
            return str(data) if data else ""
    
    def _generate_comprehensive_report(self, task: str, data: str) -> Dict[str, Any]:
        """Generate comprehensive security report using AI"""
        try:
            # Create report generation prompt
            prompt = AgentPrompts.REPORT_AGENT_PROMPT.format(
                task=task,
                input_data=data,
                agent_results=data  # For compatibility with prompt template
            )
            
            # Generate AI response
            response = self._generate_response(prompt)
            
            if not response:
                return {"error": "Failed to generate report response"}
            
            # Parse structured response
            parsed_response = self._parse_json_response(response)
            
            if parsed_response:
                # Validate and enrich the report
                return self._enrich_report_result(parsed_response, data)
            else:
                # Fallback: create structured report from text response
                return self._create_fallback_report(response, task, data)
                
        except Exception as e:
            self.logger.error(f"Error in comprehensive report generation: {e}")
            return {"error": f"Report generation failed: {str(e)}"}
    
    def _enrich_report_result(self, report: Dict[str, Any], raw_data: str) -> Dict[str, Any]:
        """Enrich report result with additional formatting and insights"""
        try:
            # Add report metadata
            report['report_metadata'] = {
                "generation_timestamp": self._get_timestamp(),
                "data_quality_score": self._calculate_data_quality_score(raw_data),
                "report_completeness": self._assess_report_completeness(report),
                "total_sections": len([k for k in report.keys() if not k.startswith('_')])
            }
            
            # Enhance executive summary
            if 'executive_summary' in report:
                report['executive_summary'] = self._enhance_executive_summary(
                    report['executive_summary'], raw_data
                )
            
            # Add report statistics
            report['report_statistics'] = self._generate_report_statistics(report, raw_data)
            
            # Format recommendations for better readability
            if 'recommendations' in report:
                report['recommendations'] = self._format_recommendations(report['recommendations'])
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error enriching report: {e}")
            return report
    
    def _create_fallback_report(self, response: str, task: str, data: str) -> Dict[str, Any]:
        """Create structured report when JSON parsing fails"""
        try:
            # Extract key information from text response
            sections = self._extract_report_sections(response)
            
            # Create basic report structure
            fallback_report = {
                "executive_summary": self._extract_executive_summary(response),
                "assessment_overview": {
                    "scope": self._extract_scope_from_data(data),
                    "methodology": "Multi-Agent Security Assessment",
                    "timeline": self._get_assessment_timeline(),
                    "key_metrics": self._extract_key_metrics_from_response(response)
                },
                "detailed_findings": self._extract_findings_from_response(response),
                "risk_summary": self._extract_risk_summary_from_response(response),
                "recommendations": self._extract_recommendations_from_response(response),
                "next_steps": self._extract_next_steps_from_response(response),
                "raw_analysis": response[:1000] + "..." if len(response) > 1000 else response,
                "parsing_note": "Report generated from text analysis due to JSON parsing limitations"
            }
            
            return self._enrich_report_result(fallback_report, data)
            
        except Exception as e:
            self.logger.error(f"Error creating fallback report: {e}")
            return {
                "executive_summary": "Security assessment completed with analysis limitations",
                "error": f"Structured report failed: {str(e)}",
                "raw_response": response[:500] + "..." if len(response) > 500 else response
            }
    
    def _extract_executive_summary(self, text: str) -> str:
        """Extract executive summary from text"""
        # Look for summary patterns
        patterns = [
            r'executive summary[:\n](.*?)(?:\n\n|$)',
            r'summary[:\n](.*?)(?:\n\n|$)',
            r'overview[:\n](.*?)(?:\n\n|$)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                summary = match.group(1).strip()
                if len(summary) > 50:  # Meaningful summary length
                    return summary[:500] + "..." if len(summary) > 500 else summary
        
        # Fallback: use first paragraph
        paragraphs = text.split('\n\n')
        if paragraphs:
            return paragraphs[0][:500] + "..." if len(paragraphs[0]) > 500 else paragraphs[0]
        
        return "Executive summary extracted from comprehensive security analysis"
    
    def _extract_findings_from_response(self, text: str) -> List[Dict[str, Any]]:
        """Extract findings from text response"""
        findings = []
        
        # Look for finding indicators
        finding_patterns = [
            r'finding[s]?[:\n](.+?)(?:\n\n|$)',
            r'identified[:\n](.+?)(?:\n\n|$)',
            r'discovered[:\n](.+?)(?:\n\n|$)'
        ]
        
        category_mapping = {
            'port': 'Network Security',
            'service': 'Service Security', 
            'vulnerability': 'Vulnerability Assessment',
            'subdomain': 'Domain Security',
            'configuration': 'Configuration Security'
        }
        
        for category, name in category_mapping.items():
            if category in text.lower():
                findings.append({
                    "category": name,
                    "findings": [f"Issues identified in {category} assessment"],
                    "severity": self._infer_severity_from_text(text),
                    "affected_systems": ["Assessment target"],
                    "evidence": f"Evidence from {category} analysis"
                })
        
        return findings if findings else [{
            "category": "Security Assessment",
            "findings": ["Security analysis completed"],
            "severity": "MEDIUM",
            "affected_systems": ["Target systems"],
            "evidence": "Comprehensive security assessment"
        }]
    
    def _extract_risk_summary_from_response(self, text: str) -> Dict[str, Any]:
        """Extract risk summary from text"""
        risk_keywords = {
            'critical': 'critical_risks',
            'high': 'high_risks',
            'medium': 'medium_risks', 
            'low': 'low_risks'
        }
        
        risk_summary = {
            'critical_risks': 0,
            'high_risks': 0,
            'medium_risks': 0,
            'low_risks': 0,
            'total_risks': 0
        }
        
        for keyword, risk_type in risk_keywords.items():
            count = len(re.findall(keyword, text, re.IGNORECASE))
            risk_summary[risk_type] = count
        
        risk_summary['total_risks'] = sum([
            risk_summary['critical_risks'],
            risk_summary['high_risks'],
            risk_summary['medium_risks'],
            risk_summary['low_risks']
        ])
        
        return risk_summary
    
    def _extract_recommendations_from_response(self, text: str) -> List[Dict[str, Any]]:
        """Extract recommendations from text response"""
        recommendations = []
        
        # Look for recommendation patterns
        rec_patterns = [
            r'recommend[s]?\s*[:\-]?\s*([^.!?\n]+)',
            r'should\s+([^.!?\n]+)',
            r'suggest[s]?\s*[:\-]?\s*([^.!?\n]+)'
        ]
        
        for pattern in rec_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches[:5]:  # Top 5 recommendations
                if len(match.strip()) > 10:
                    recommendations.append({
                        "category": "Security Improvement",
                        "priority": self._infer_priority_from_text(match),
                        "recommendation": match.strip(),
                        "rationale": "Based on security assessment findings",
                        "implementation": {
                            "effort": "To be determined",
                            "timeline": "Based on priority level",
                            "resources": "Security team"
                        }
                    })
        
        return recommendations if recommendations else [{
            "category": "General Security",
            "priority": "MEDIUM",
            "recommendation": "Continue regular security assessments",
            "rationale": "Maintain security posture through ongoing evaluation"
        }]
    
    def _infer_severity_from_text(self, text: str) -> str:
        """Infer severity level from text"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['critical', 'severe', 'urgent']):
            return 'CRITICAL'
        elif any(word in text_lower for word in ['high', 'important', 'significant']):
            return 'HIGH'  
        elif any(word in text_lower for word in ['medium', 'moderate']):
            return 'MEDIUM'
        elif any(word in text_lower for word in ['low', 'minor']):
            return 'LOW'
        else:
            return 'MEDIUM'
    
    def _infer_priority_from_text(self, text: str) -> str:
        """Infer priority from recommendation text"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['immediately', 'urgent', 'critical']):
            return 'CRITICAL'
        elif any(word in text_lower for word in ['important', 'should', 'must']):
            return 'HIGH'
        elif any(word in text_lower for word in ['consider', 'might', 'could']):
            return 'LOW'
        else:
            return 'MEDIUM'
    
    def _calculate_data_quality_score(self, data: str) -> float:
        """Calculate data quality score for report"""
        try:
            base_score = 0.5
            
            # Increase score based on data completeness
            if len(data) > 1000:
                base_score += 0.2
            if 'tool_results' in data.lower():
                base_score += 0.1
            if 'analysis' in data.lower():
                base_score += 0.1
            if 'recommendation' in data.lower():
                base_score += 0.1
                
            return min(base_score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error calculating data quality score: {e}")
            return 0.5
    
    def _assess_report_completeness(self, report: Dict[str, Any]) -> str:
        """Assess completeness of generated report"""
        required_sections = [
            'executive_summary', 'assessment_overview', 'detailed_findings',
            'risk_summary', 'recommendations'
        ]
        
        present_sections = sum(1 for section in required_sections if section in report)
        completeness_ratio = present_sections / len(required_sections)
        
        if completeness_ratio >= 0.8:
            return 'Complete'
        elif completeness_ratio >= 0.6:
            return 'Mostly Complete'
        elif completeness_ratio >= 0.4:
            return 'Partial'
        else:
            return 'Limited'
    
    def _generate_report_statistics(self, report: Dict[str, Any], data: str) -> Dict[str, Any]:
        """Generate statistics about the report"""
        return {
            "total_findings": len(report.get('detailed_findings', [])),
            "total_recommendations": len(report.get('recommendations', [])),
            "data_sources_analyzed": len(re.findall(r'tool|analysis|result', data, re.IGNORECASE)),
            "report_length": len(str(report)),
            "generation_method": "AI-assisted with fallback analysis"
        }
    
    def _determine_report_type(self, task: str) -> str:
        """Determine the type of report being generated"""
        task_lower = task.lower()
        
        if 'comprehensive' in task_lower or 'complete' in task_lower:
            return 'Comprehensive Security Assessment Report'
        elif 'vulnerability' in task_lower:
            return 'Vulnerability Assessment Report'
        elif 'network' in task_lower or 'port' in task_lower:
            return 'Network Security Assessment Report'
        elif 'domain' in task_lower or 'subdomain' in task_lower:
            return 'Domain Security Assessment Report'
        else:
            return 'Security Assessment Report'
    
    def _identify_data_sources(self, data: str) -> List[str]:
        """Identify data sources used in the report"""
        sources = []
        
        if 'nmap' in data.lower() or 'port scan' in data.lower():
            sources.append('Network Port Scanning (Nmap)')
        if 'subfinder' in data.lower() or 'subdomain' in data.lower():
            sources.append('Subdomain Enumeration (Subfinder)')
        if 'analysis' in data.lower():
            sources.append('Security Analysis Engine')
        if 'tool_results' in data.lower():
            sources.append('Security Tool Execution')
            
        return sources if sources else ['Security Assessment Tools']
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        return datetime.now().isoformat()
    
    # Helper methods for text extraction and processing
    def _extract_scope_from_data(self, data: str) -> str:
        """Extract assessment scope from data"""
        if 'assessment_scope' in data.lower():
            match = re.search(r'assessment_scope[:\s]+([^\n]+)', data, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return "Multi-Agent Security Assessment"
    
    def _get_assessment_timeline(self) -> str:
        """Get assessment timeline"""
        return f"Assessment completed on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    
    def _extract_key_metrics_from_response(self, response: str) -> str:
        """Extract key metrics from response text"""
        # Look for numeric indicators
        numbers = re.findall(r'\d+', response)
        if numbers:
            return f"Assessment identified {len(numbers)} quantifiable security indicators"
        return "Qualitative security assessment metrics"
    
    def _extract_report_sections(self, text: str) -> Dict[str, str]:
        """Extract different sections from report text"""
        sections = {}
        
        section_patterns = {
            'summary': r'summary[:\n](.*?)(?:\n\n|$)',
            'findings': r'finding[s]?[:\n](.*?)(?:\n\n|$)',
            'recommendations': r'recommendation[s]?[:\n](.*?)(?:\n\n|$)',
            'risks': r'risk[s]?[:\n](.*?)(?:\n\n|$)'
        }
        
        for section_name, pattern in section_patterns.items():
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                sections[section_name] = match.group(1).strip()
        
        return sections
    
    def _extract_next_steps_from_response(self, text: str) -> List[str]:
        """Extract next steps from response"""
        next_steps = []
        
        # Look for next step indicators
        patterns = [
            r'next step[s]?[:\n](.+?)(?:\n\n|$)',
            r'follow[- ]up[:\n](.+?)(?:\n\n|$)',
            r'action[s]? required[:\n](.+?)(?:\n\n|$)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                steps_text = match.group(1).strip()
                next_steps.extend([step.strip() for step in steps_text.split('\n') if step.strip()])
                break
        
        return next_steps if next_steps else [
            "Review assessment findings",
            "Prioritize recommendations based on risk level",
            "Implement security improvements",
            "Schedule follow-up assessment"
        ]
    
    def _enhance_executive_summary(self, summary: str, data: str) -> str:
        """Enhance executive summary with data-driven insights"""
        try:
            # Add quantitative insights if available
            if 'tool_results' in data.lower():
                tool_count = len(re.findall(r'tool', data, re.IGNORECASE))
                summary += f" This assessment utilized {tool_count} security tools for comprehensive analysis."
            
            if 'analysis_results' in data.lower():
                analysis_count = len(re.findall(r'analysis', data, re.IGNORECASE))
                summary += f" {analysis_count} detailed security analyses were performed."
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error enhancing executive summary: {e}")
            return summary
    
    def _format_recommendations(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format recommendations for better presentation"""
        try:
            formatted_recs = []
            
            for rec in recommendations:
                formatted_rec = rec.copy()
                
                # Add urgency scoring
                priority = rec.get('priority', 'MEDIUM').upper()
                urgency_scores = {'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25}
                formatted_rec['urgency_score'] = urgency_scores.get(priority, 50)
                
                # Add estimated timeline based on priority
                timeline_map = {
                    'CRITICAL': 'Immediate (0-24 hours)',
                    'HIGH': '1-7 days',
                    'MEDIUM': '1-4 weeks', 
                    'LOW': '1-3 months'
                }
                
                if 'implementation' in formatted_rec and isinstance(formatted_rec['implementation'], dict):
                    formatted_rec['implementation']['timeline'] = timeline_map.get(priority, '1-4 weeks')
                
                formatted_recs.append(formatted_rec)
            
            # Sort by urgency score
            return sorted(formatted_recs, key=lambda x: x.get('urgency_score', 0), reverse=True)
            
        except Exception as e:
            self.logger.error(f"Error formatting recommendations: {e}")
            return recommendations