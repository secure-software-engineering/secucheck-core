package de.fraunhofer.iem.secucheck.analysis.internal.taint;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.eclipse.emf.common.util.EList;

import boomerang.Query;
import boomerang.callgraph.ObservableICFG;
import boomerang.callgraph.ObservableStaticICFG;
import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import de.fraunhofer.iem.secucheck.marker.AnalysisResult;
import de.fraunhofer.iem.secucheck.marker.Issue;
import de.fraunhofer.iem.secucheck.marker.Marker;
import de.fraunhofer.iem.secucheck.marker.MarkerFactory;
import de.fraunhofer.iem.secucheck.marker.MarkerType;

import de.fraunhofer.iem.secucheck.query.Method;
import de.fraunhofer.iem.secucheck.query.PartialTaintFlow;
import de.fraunhofer.iem.secucheck.query.TaintFlow;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.toolkits.ide.icfg.BiDiInterproceduralCFG;
import soot.tagkit.AbstractHost;
import sync.pds.solver.nodes.Node;

public class TaintAnalysis {

	private final TaintFlow flowQuery;
	private final AnalysisResult result;
	private final ObservableICFG<Unit, SootMethod> icfg;
	
	public TaintAnalysis(BiDiInterproceduralCFG<Unit, SootMethod> icfg, 
			TaintFlow flowQuery,AnalysisResult result) {
		this.result = result;
		this.flowQuery = flowQuery;
		this.icfg = new ObservableStaticICFG(icfg);
		
		// Resolve all methods. This is necessary if a flow participant is not part of
		// the user code...
		// See: https://github.com/secure-software-engineering/secucheck/issues/11
		for (Method method : Utility.getMethods(flowQuery)) {
			Utility.getSootMethod(method);
		}
	}
	
	public void run() {	
		
		Map<PartialTaintFlow, Pair<Query>> allReachMap = 
				new HashMap<PartialTaintFlow, Pair<Query>>();
		
		for (PartialTaintFlow originalFlow : flowQuery.getPartialTaintFlows()) {
			
			SingleFlowAnalyzer flowAnalyzer = 
					new SingleFlowAnalyzer(originalFlow, icfg);
			
			Map<PartialTaintFlow, Pair<Query>> reachMap = flowAnalyzer.analyze();
			
			if (reachMap.size() == 0) {
				allReachMap.clear();
				break;
			}
			
			allReachMap.putAll(reachMap);		
		}
		
		reportReachingTaintFlows(allReachMap);
	}	
	
	

	private void reportReachingTaintFlows(Map<PartialTaintFlow, Pair<Query>> reachingFlows) {
		if (reachingFlows.size() > 0) {
			Issue issue = MarkerFactory.eINSTANCE.createIssue();
			issue.setMessage(this.flowQuery.getReportMessage());
			
			reachingFlows.forEach((partialFlow, pair)-> 
			createTaintFlowMarkers(partialFlow, issue,
						pair.getFirst().asNode(), pair.getSecond().asNode()));
			
			result.getIssues().add(issue);
		}
	}		
	
	private void createTaintFlowMarkers(PartialTaintFlow partialFlow, Issue issue, 
			Node<Statement, Val> source, Node<Statement, Val> sink) {
		// System.out.println("TAINT! source = " + source + ", sink = " + sink);
		
		// This list may contain null elements.
		List<Marker> markers = new ArrayList<Marker>();
		
		// Usage markers for source and sink
		if (flowQuery.getReportLocation() == null || flowQuery.getReportLocation() != 2) {
			
			markers.add(createMarker(source.stmt().getMethod(), 
					((AbstractHost) source.stmt().getUnit().get()).getJavaSourceStartLineNumber(),
					MarkerType.SOURCE_METHOD_USAGE));

			// Definition markers for source
			SootMethod sourceMethodDefinition = Utility.findSourceMethodDefinition(partialFlow, source.stmt().getMethod(),
					source.stmt().getUnit().get());
			
			if (sourceMethodDefinition != null) {
				markers.add(createMarker(sourceMethodDefinition, 
						sourceMethodDefinition.getJavaSourceStartLineNumber(), MarkerType.SOURCE_METHOD_DEFINITION));
			}
		}
		
		if (flowQuery.getReportLocation() == null || flowQuery.getReportLocation() != 1) {
			
			markers.add(createMarker(sink.stmt().getMethod(), 
					((AbstractHost) sink.stmt().getUnit().get()).getJavaSourceStartLineNumber(), 
					MarkerType.SINK_METHOD_USAGE));

			// Definition markers for sink
			SootMethod sinkMethodDefinition = Utility.findSinkMethodDefinition(partialFlow, sink.stmt().getMethod(),
					sink.stmt().getUnit().get());
			
			if (sinkMethodDefinition != null) {
				markers.add(createMarker(sinkMethodDefinition,
						sinkMethodDefinition.getJavaSourceStartLineNumber(), MarkerType.SINK_METHOD_DEFINITION));
			}
		}
		
		// Add all markers that are not null.
		for (Marker marker : markers) {
			if (marker != null) {	
				marker.setIssue(issue);
				MarkerType parentMarkerType = null;
				if (marker.getMarkerType() == MarkerType.SOURCE_METHOD_USAGE) {
					parentMarkerType = MarkerType.SOURCE_METHOD_DEFINITION;
				} else if (marker.getMarkerType() == MarkerType.SINK_METHOD_USAGE) {
					parentMarkerType = MarkerType.SINK_METHOD_DEFINITION;
				}				
				EList<Marker> containmentList = issue.getMarkers();
				if (parentMarkerType != null) {
					for (Marker definitionMarker : markers) {
						if (definitionMarker != null && definitionMarker.getMarkerType() == parentMarkerType) {
							containmentList = definitionMarker.getSubMarkers();
						}
					}
				}
				containmentList.add(marker);
			}
		}
	}
	
	
	
	private Marker createMarker(SootMethod method, int lineNumber, MarkerType markerType) {
		String className = method.getDeclaringClass().getName();
		String methodSignature = method.getSignature();
		// Note: This can be used as SOURCE_ID attribute for the marker, optionally.
		// final int stmtId = calculateStatementId(errorLocation);
		Marker marker = MarkerFactory.eINSTANCE.createMarker();
		marker.setMarkerType(markerType);
		marker.setClassName(className);
		marker.setLineNumber(lineNumber);
		marker.setMethodSignature(methodSignature.substring(1, methodSignature.length() - 1));
		return marker;
	}
}
