from typing import Dict, Any, List
from .base_agent import BaseAgent
from utils.agent_prompt import AgentPrompts
import logging
import json
import re

class AnalysisAssessmentRecommendationAgent(BaseAgent):
    """Agent specialized in security analysis, assessment, and recommendations"""
    
    def __init__(self, model_name: str = "llama3.2"):
        super().__init__(model_name, "AnalysisAssessmentRecommendationAgent")
        self.logger.info("Analysis Assessment Recommendation Agent initialized")
    
    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute security analysis, assessment, and provide recommendations
        """
        try:
            task = input_data.get('task', '')
            analysis_data = input_data.get('input_data', '')
            
            self.logger.info(f"Performing analysis for task: {task}")
            self.logger.info(f"Analysis data type: {type(analysis_data)}")
            
            # Normalize input data for analysis
            processed_data = self._normalize_analysis_data(analysis_data)
            
            if not processed_data:
                return {
                    "status": "error",
                    "message": "No valid data provided for analysis",
                    "agent": "AnalysisAssessmentRecommendationAgent"
                }
            
            # Perform comprehensive analysis
            analysis_result = self._perform_comprehensive_analysis(task, processed_data)
            
            if analysis_result.get('error'):
                return {
                    "status": "error",
                    "message": analysis_result['error'],
                    "agent": "AnalysisAssessmentRecommendationAgent"
                }
            
            # Structure the final result
            return {
                "status": "success",
                "agent": "AnalysisAssessmentRecommendationAgent",
                "task": task,
                "analysis": analysis_result,
                "metadata": {
                    "analysis_timestamp": self._get_timestamp(),
                    "data_source": self._identify_data_source(processed_data),
                    "analysis_scope": self._determine_analysis_scope(task, processed_data)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error in analysis execution: {e}")
            return {
                "status": "error",
                "message": f"Analysis execution failed: {str(e)}",
                "agent": "AnalysisAssessmentRecommendationAgent"
            }
    
    def _normalize_analysis_data(self, data: Any) -> str:
        """Normalize various input data formats for analysis"""
        try:
            if isinstance(data, str):
                return data
            elif isinstance(data, dict):
                # Handle tool execution results
                if 'result' in data and isinstance(data['result'], dict):
                    # Extract meaningful data from tool results
                    tool_result = data['result']
                    formatted_parts = []
                    
                    # Add tool information if available
                    if 'tool_used' in data:
                        formatted_parts.append(f"Tool: {data['tool_used']}")
                    
                    # Process the actual result data
                    for key, value in tool_result.items():
                        if isinstance(value, (list, dict)):
                            formatted_parts.append(f"{key}: {json.dumps(value, indent=2)}")
                        else:
                            formatted_parts.append(f"{key}: {value}")
                    
                    return "\n".join(formatted_parts)
                else:
                    # Convert dict to structured string
                    return json.dumps(data, indent=2, ensure_ascii=False)
            elif isinstance(data, list):
                return json.dumps(data, indent=2, ensure_ascii=False)
            else:
                return str(data)
        except Exception as e:
            self.logger.error(f"Error normalizing data: {e}")
            return str(data) if data else ""
    
    def _perform_comprehensive_analysis(self, task: str, data: str) -> Dict[str, Any]:
        """Perform comprehensive security analysis using AI"""
        try:
            # Create analysis prompt
            prompt = AgentPrompts.ANALYSIS_ASSESSMENT_RECOMMENDATION_PROMPT.format(
                task=task,
                input_data=data
            )
            
            # Generate AI response
            response = self._generate_response(prompt)
            
            if not response:
                return {"error": "Failed to generate analysis response"}
            
            # Parse structured response
            parsed_response = self._parse_json_response(response)
            
            if parsed_response:
                # Validate and enrich the analysis
                return self._enrich_analysis_result(parsed_response, data)
            else:
                # Fallback: create structured analysis from text response
                return self._create_fallback_analysis(response, task, data)
                
        except Exception as e:
            self.logger.error(f"Error in comprehensive analysis: {e}")
            return {"error": f"Analysis failed: {str(e)}"}
    
    def _enrich_analysis_result(self, analysis: Dict[str, Any], raw_data: str) -> Dict[str, Any]:
        """Enrich analysis result with additional insights"""
        try:
            # Add data characteristics analysis
            data_characteristics = self._analyze_data_characteristics(raw_data)
            analysis['data_characteristics'] = data_characteristics
            
            # Enhance risk assessment with quantitative metrics
            if 'risk_assessment' in analysis:
                analysis['risk_assessment'] = self._enhance_risk_assessment(
                    analysis['risk_assessment'], raw_data
                )
            
            # Add priority matrix for recommendations
            if 'recommendations' in analysis and isinstance(analysis['recommendations'], list):
                analysis['recommendations'] = self._prioritize_recommendations(
                    analysis['recommendations']
                )
            
            # Add executive summary
            analysis['executive_summary'] = self._generate_executive_summary(analysis)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error enriching analysis: {e}")
            return analysis
    
    def _create_fallback_analysis(self, response: str, task: str, data: str) -> Dict[str, Any]:
        """Create structured analysis when JSON parsing fails"""
        try:
            # Extract key insights from text response
            insights = self._extract_insights_from_text(response)
            
            # Create basic structure
            fallback_analysis = {
                "analysis": response[:1000] + "..." if len(response) > 1000 else response,
                "risk_assessment": {
                    "level": self._infer_risk_level(response),
                    "score": self._calculate_risk_score(data),
                    "factors": self._extract_risk_factors(response),
                    "impact": "Requires detailed review",
                    "likelihood": "To be determined"
                },
                "recommendations": self._extract_recommendations_from_text(response),
                "key_findings": insights,
                "data_analysis": self._analyze_data_patterns(data)
            }
            
            return self._enrich_analysis_result(fallback_analysis, data)
            
        except Exception as e:
            self.logger.error(f"Error creating fallback analysis: {e}")
            return {
                "analysis": "Analysis completed with limitations",
                "error": f"Structured analysis failed: {str(e)}",
                "raw_response": response[:500] + "..." if len(response) > 500 else response
            }
    
    def _analyze_data_characteristics(self, data: str) -> Dict[str, Any]:
        """Analyze characteristics of the input data"""
        characteristics = {
            "data_size": len(data),
            "data_type": "unknown",
            "structure": "unstructured",
            "security_indicators": []
        }
        
        try:
            # Determine data type
            if any(indicator in data.lower() for indicator in ['port', 'tcp', 'udp', 'open', 'closed']):
                characteristics["data_type"] = "port_scan_results"
            elif any(indicator in data.lower() for indicator in ['subdomain', 'domain', 'dns']):
                characteristics["data_type"] = "domain_enumeration"
            elif any(indicator in data.lower() for indicator in ['vulnerability', 'cve', 'exploit']):
                characteristics["data_type"] = "vulnerability_data"
            elif 'json' in data or ('{' in data and '}' in data):
                characteristics["structure"] = "structured"
            
            # Identify security indicators
            security_patterns = {
                'ip_addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                'domains': r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
                'ports': r'\b\d{1,5}/(?:tcp|udp)\b',
                'vulnerabilities': r'\b(?:CVE-\d{4}-\d{4,}|critical|high|medium|low)\b'
            }
            
            for indicator_type, pattern in security_patterns.items():
                matches = re.findall(pattern, data, re.IGNORECASE)
                if matches:
                    characteristics["security_indicators"].append({
                        "type": indicator_type,
                        "count": len(matches),
                        "samples": matches[:5]  # First 5 matches as samples
                    })
            
        except Exception as e:
            self.logger.error(f"Error analyzing data characteristics: {e}")
        
        return characteristics
    
    def _enhance_risk_assessment(self, risk_assessment: Dict[str, Any], data: str) -> Dict[str, Any]:
        """Enhance risk assessment with data-driven insights"""
        try:
            # Calculate confidence score based on data quality
            confidence_score = self._calculate_confidence_score(data)
            risk_assessment['confidence_score'] = confidence_score
            
            # Add quantitative metrics
            risk_assessment['metrics'] = self._calculate_risk_metrics(data)
            
            # Add timeline estimation
            risk_assessment['timeline'] = self._estimate_risk_timeline(risk_assessment.get('level', 'UNKNOWN'))
            
        except Exception as e:
            self.logger.error(f"Error enhancing risk assessment: {e}")
        
        return risk_assessment
    
    def _prioritize_recommendations(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add priority scoring to recommendations"""
        try:
            priority_weights = {
                'CRITICAL': 100,
                'HIGH': 75,
                'MEDIUM': 50,
                'LOW': 25
            }
            
            for rec in recommendations:
                priority = rec.get('priority', 'MEDIUM').upper()
                urgency_score = priority_weights.get(priority, 50)
                
                # Add impact factors
                impact_factors = rec.get('impact_factors', [])
                if impact_factors:
                    urgency_score += len(impact_factors) * 5
                
                rec['urgency_score'] = urgency_score
                rec['estimated_effort'] = self._estimate_implementation_effort(rec)
            
            # Sort by urgency score
            return sorted(recommendations, key=lambda x: x.get('urgency_score', 0), reverse=True)
            
        except Exception as e:
            self.logger.error(f"Error prioritizing recommendations: {e}")
            return recommendations
    
    def _generate_executive_summary(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary from analysis"""
        try:
            risk_level = analysis.get('risk_assessment', {}).get('level', 'UNKNOWN')
            rec_count = len(analysis.get('recommendations', []))
            
            summary = {
                "overall_risk": risk_level,
                "total_recommendations": rec_count,
                "critical_issues": self._count_critical_issues(analysis),
                "key_concerns": self._extract_key_concerns(analysis),
                "immediate_actions": self._extract_immediate_actions(analysis)
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating executive summary: {e}")
            return {"error": "Failed to generate summary"}
    
    def _extract_insights_from_text(self, text: str) -> List[str]:
        """Extract key insights from text response"""
        insights = []
        try:
            # Split text into sentences
            sentences = re.split(r'[.!?]+', text)
            
            # Look for insight indicators
            insight_patterns = [
                r'found|discovered|identified|detected',
                r'vulnerable|weakness|risk|threat',
                r'recommend|suggest|should|must',
                r'critical|important|significant'
            ]
            
            for sentence in sentences:
                sentence = sentence.strip()
                if len(sentence) > 20:  # Meaningful sentence length
                    for pattern in insight_patterns:
                        if re.search(pattern, sentence, re.IGNORECASE):
                            insights.append(sentence)
                            break
            
            return insights[:10]  # Top 10 insights
            
        except Exception as e:
            self.logger.error(f"Error extracting insights: {e}")
            return ["Analysis completed with extracted insights"]
    
    def _infer_risk_level(self, text: str) -> str:
        """Infer risk level from text analysis"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['critical', 'severe', 'urgent', 'immediate']):
            return 'CRITICAL'
        elif any(word in text_lower for word in ['high', 'important', 'significant']):
            return 'HIGH'
        elif any(word in text_lower for word in ['medium', 'moderate', 'considerable']):
            return 'MEDIUM'
        elif any(word in text_lower for word in ['low', 'minor', 'minimal']):
            return 'LOW'
        else:
            return 'MEDIUM'
    
    def _calculate_risk_score(self, data: str) -> int:
        """Calculate numeric risk score based on data analysis"""
        score = 5  # Base score
        
        try:
            # Increase score based on security indicators
            if re.search(r'open.*port', data, re.IGNORECASE):
                score += 2
            if re.search(r'vulnerable|exploit|cve', data, re.IGNORECASE):
                score += 3
            if re.search(r'critical|high', data, re.IGNORECASE):
                score += 2
            
            # Decrease score for positive indicators
            if re.search(r'secure|protected|patched', data, re.IGNORECASE):
                score -= 1
            
            return min(max(score, 1), 10)  # Clamp between 1-10
            
        except Exception as e:
            self.logger.error(f"Error calculating risk score: {e}")
            return 5
    
    def _extract_risk_factors(self, text: str) -> List[str]:
        """Extract risk factors from text"""
        risk_factors = []
        
        try:
            # Common risk factor patterns
            patterns = [
                r'open port[s]?\s*\d+',
                r'vulnerable\s+to\s+\w+',
                r'unpatched\s+\w+',
                r'weak\s+\w+',
                r'exposed\s+\w+'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                risk_factors.extend(matches)
            
            return list(set(risk_factors))  # Remove duplicates
            
        except Exception as e:
            self.logger.error(f"Error extracting risk factors: {e}")
            return ["Risk factors identified in analysis"]
    
    def _extract_recommendations_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Extract recommendations from text response"""
        recommendations = []
        
        try:
            # Look for recommendation indicators
            rec_patterns = [
                r'recommend[s]?\s+([^.!?]+)',
                r'should\s+([^.!?]+)',
                r'must\s+([^.!?]+)',
                r'suggest[s]?\s+([^.!?]+)'
            ]
            
            for pattern in rec_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    if len(match.strip()) > 10:
                        recommendations.append({
                            "priority": "MEDIUM",
                            "action": match.strip(),
                            "description": f"Recommendation extracted from analysis: {match.strip()}",
                            "timeline": "To be determined"
                        })
            
            return recommendations[:5]  # Top 5 recommendations
            
        except Exception as e:
            self.logger.error(f"Error extracting recommendations: {e}")
            return [{
                "priority": "MEDIUM",
                "action": "Review analysis results",
                "description": "Manual review required for detailed recommendations"
            }]
    
    def _analyze_data_patterns(self, data: str) -> Dict[str, Any]:
        """Analyze patterns in the data"""
        patterns = {
            "total_size": len(data),
            "structure_indicators": [],
            "security_patterns": [],
            "data_quality": "unknown"
        }
        
        try:
            # Check for structured data indicators
            if '{' in data and '}' in data:
                patterns["structure_indicators"].append("JSON-like structure")
            if '<' in data and '>' in data:
                patterns["structure_indicators"].append("XML/HTML-like structure")
            if ',' in data and '\n' in data:
                patterns["structure_indicators"].append("CSV-like structure")
            
            # Analyze data quality
            if len(data) > 100:
                patterns["data_quality"] = "sufficient"
            elif len(data) > 50:
                patterns["data_quality"] = "limited"
            else:
                patterns["data_quality"] = "minimal"
            
        except Exception as e:
            self.logger.error(f"Error analyzing data patterns: {e}")
        
        return patterns
    
    def _calculate_confidence_score(self, data: str) -> float:
        """Calculate confidence score for analysis"""
        try:
            base_score = 0.5
            
            # Increase confidence based on data completeness
            if len(data) > 500:
                base_score += 0.2
            if len(data) > 1000:
                base_score += 0.1
            
            # Increase confidence for structured data
            if '{' in data or '[' in data:
                base_score += 0.1
            
            # Increase confidence for security-specific data
            if any(term in data.lower() for term in ['port', 'scan', 'vulnerability', 'security']):
                base_score += 0.1
            
            return min(base_score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error calculating confidence score: {e}")
            return 0.5
    
    def _calculate_risk_metrics(self, data: str) -> Dict[str, Any]:
        """Calculate quantitative risk metrics"""
        metrics = {
            "exposure_score": 0,
            "complexity_score": 0,
            "urgency_score": 0
        }
        
        try:
            # Calculate exposure based on open ports, services, etc.
            open_ports = len(re.findall(r'open', data, re.IGNORECASE))
            metrics["exposure_score"] = min(open_ports * 10, 100)
            
            # Calculate complexity based on data volume and variety
            metrics["complexity_score"] = min(len(data) // 100, 100)
            
            # Calculate urgency based on critical indicators
            critical_indicators = len(re.findall(r'critical|vulnerable|exploit', data, re.IGNORECASE))
            metrics["urgency_score"] = min(critical_indicators * 25, 100)
            
        except Exception as e:
            self.logger.error(f"Error calculating risk metrics: {e}")
        
        return metrics
    
    def _estimate_risk_timeline(self, risk_level: str) -> Dict[str, str]:
        """Estimate timeline based on risk level"""
        timelines = {
            'CRITICAL': {
                'response_time': 'Immediate (0-24 hours)',
                'resolution_time': '1-3 days',
                'review_frequency': 'Daily'
            },
            'HIGH': {
                'response_time': '24-48 hours',
                'resolution_time': '1-2 weeks',
                'review_frequency': 'Weekly'
            },
            'MEDIUM': {
                'response_time': '1-3 days',
                'resolution_time': '2-4 weeks',
                'review_frequency': 'Bi-weekly'
            },
            'LOW': {
                'response_time': '1 week',
                'resolution_time': '1-2 months',
                'review_frequency': 'Monthly'
            }
        }
        
        return timelines.get(risk_level, timelines['MEDIUM'])
    
    def _estimate_implementation_effort(self, recommendation: Dict[str, Any]) -> str:
        """Estimate implementation effort for recommendations"""
        priority = recommendation.get('priority', 'MEDIUM').upper()
        description = recommendation.get('description', '').lower()
        
        # Simple heuristic based on keywords and priority
        if priority == 'CRITICAL' or any(word in description for word in ['patch', 'update', 'fix']):
            return 'Low-Medium (1-3 days)'
        elif any(word in description for word in ['implement', 'configure', 'deploy']):
            return 'Medium (1-2 weeks)'
        elif any(word in description for word in ['redesign', 'rebuild', 'replace']):
            return 'High (1-2 months)'
        else:
            return 'Medium (1-2 weeks)'
    
    def _count_critical_issues(self, analysis: Dict[str, Any]) -> int:
        """Count critical issues from analysis"""
        count = 0
        try:
            risk_level = analysis.get('risk_assessment', {}).get('level', '')
            if risk_level == 'CRITICAL':
                count += 1
            
            recommendations = analysis.get('recommendations', [])
            for rec in recommendations:
                if rec.get('priority') == 'CRITICAL':
                    count += 1
            
        except Exception as e:
            self.logger.error(f"Error counting critical issues: {e}")
        
        return count
    
    def _extract_key_concerns(self, analysis: Dict[str, Any]) -> List[str]:
        """Extract key concerns from analysis"""
        concerns = []
        try:
            # Extract from risk factors
            risk_factors = analysis.get('risk_assessment', {}).get('factors', [])
            concerns.extend(risk_factors[:3])  # Top 3 risk factors
            
            # Extract from high-priority recommendations
            recommendations = analysis.get('recommendations', [])
            for rec in recommendations:
                if rec.get('priority') in ['CRITICAL', 'HIGH']:
                    concerns.append(rec.get('action', ''))
            
            return concerns[:5]  # Top 5 concerns
            
        except Exception as e:
            self.logger.error(f"Error extracting key concerns: {e}")
            return ["Review required for detailed concerns"]
    
    def _extract_immediate_actions(self, analysis: Dict[str, Any]) -> List[str]:
        """Extract immediate actions from analysis"""
        actions = []
        try:
            recommendations = analysis.get('recommendations', [])
            for rec in recommendations:
                if rec.get('priority') == 'CRITICAL':
                    actions.append(rec.get('action', ''))
            
            if not actions:
                # Get highest priority recommendations
                sorted_recs = sorted(recommendations, 
                                   key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x.get('priority', 'LOW'), 1),
                                   reverse=True)
                actions = [rec.get('action', '') for rec in sorted_recs[:2]]
            
            return actions[:3]  # Top 3 immediate actions
            
        except Exception as e:
            self.logger.error(f"Error extracting immediate actions: {e}")
            return ["Review analysis and prioritize actions"]
    
    def _identify_data_source(self, data: str) -> str:
        """Identify the source type of the data"""
        if 'nmap' in data.lower() or any(port_indicator in data.lower() for port_indicator in ['port', 'tcp', 'udp']):
            return 'Port Scan Results'
        elif 'subfinder' in data.lower() or 'subdomain' in data.lower():
            return 'Subdomain Enumeration'
        elif 'vulnerability' in data.lower() or 'cve' in data.lower():
            return 'Vulnerability Assessment'
        elif len(data) > 0:
            return 'Security Data'
        else:
            return 'Unknown'
    
    def _determine_analysis_scope(self, task: str, data: str) -> str:
        """Determine the scope of analysis"""
        task_lower = task.lower()
        
        if 'comprehensive' in task_lower or 'full' in task_lower:
            return 'Comprehensive Security Analysis'
        elif 'risk' in task_lower:
            return 'Risk Assessment'
        elif 'recommend' in task_lower:
            return 'Recommendations Focus'
        elif len(data) > 1000:
            return 'Detailed Analysis'
        else:
            return 'Standard Analysis'
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()