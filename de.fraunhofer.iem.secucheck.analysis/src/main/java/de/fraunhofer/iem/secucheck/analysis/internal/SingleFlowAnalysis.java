package de.fraunhofer.iem.secucheck.analysis.internal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.Sets;
import com.google.common.collect.Table;

import boomerang.BackwardQuery;
import boomerang.Boomerang;
import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.results.BackwardBoomerangResults;
import boomerang.results.ForwardBoomerangResults;
import boomerang.results.AbstractBoomerangResults.Context;
import boomerang.scene.AnalysisScope;
import boomerang.scene.ControlFlowGraph.Edge;
import boomerang.scene.Val;
import boomerang.scene.jimple.SootCallGraph;
import boomerang.util.AccessPath;
import de.fraunhofer.iem.secucheck.analysis.Analysis;
import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.SameTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.LocationDetails;
import de.fraunhofer.iem.secucheck.analysis.result.LocationType;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;
import soot.Body;
import soot.SootMethod;
import soot.jimple.JimpleBody;
import soot.jimple.internal.JNopStmt;
import wpds.impl.Weight;
import wpds.impl.Weight.NoWeight;

class SingleFlowAnalysis implements Analysis {

	private final TaintFlowQueryImpl singleFlow;
	private final SootCallGraph sootCallGraph;
	private final AnalysisResultListener resultListener;
	
	public SingleFlowAnalysis(TaintFlowQueryImpl singleFlow,
			SootCallGraph sootCallGraph, 
			AnalysisResultListener resultListener) {
		this.singleFlow = singleFlow;
		this.sootCallGraph = sootCallGraph;
		this.resultListener = resultListener;
	}
	
	@Override
	public AnalysisResult run() {
		
		TaintFlowQueryResult result = new TaintFlowQueryResult();
		List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> reachMap;
		
		// Propogator-less execution.
		if (isPropogatorless(this.singleFlow)) {
			reachMap = analyzePlainFlow(singleFlow);
		} else {
			reachMap = analyzePropogatorFlow(singleFlow);
		}
		
		result.addQueryResultPairs(reachMap);
		return result;
	}
	
	public List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> 
		analyzePlainFlow(TaintFlowQueryImpl singleFlow){
		
		List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> 
			reachMap = new ArrayList<>();
		
		AnalysisScope analysisScope = getAnalysisScope(singleFlow);
		Boomerang boomerang = getBoomerang(analysisScope);
		Seeds seeds = computeSeeds(analysisScope);
		
		if (seeds.getSources().size() != 0 && seeds.getSinks().size() != 0) {
			
			List<Method> sanitizers = getSanitizers(singleFlow);
			Map<SootMethod, Body> oldMethodBodies = new HashMap<SootMethod, Body>();
			
			try	{
				oldMethodBodies = setEmptySootBodies(sanitizers);
				reachMap =  analyzeInternal(boomerang, singleFlow, seeds.getSources(),
						seeds.getSinks());
			} finally {
				oldMethodBodies.entrySet().forEach( entry ->
					entry.getKey().setActiveBody(entry.getValue()));
			}
		}
		
		return reachMap;
	}
	
	public List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> 
		analyzePropogatorFlow(TaintFlowQueryImpl singleFlow){

		/* Each occurance of a propogator/desanitizer would break a single
		 * TaintFlow into two logical TaintFlows, this generates 
		 * these TaintFlows. */	
		
		TaintFlowQueryImpl newQuery1 = new TaintFlowQueryImpl(), 
				newQuery2 = new TaintFlowQueryImpl(); 
		
		newQuery1.getFrom().addAll(singleFlow.getFrom());
		
		if (singleFlow.getNotThrough() != null)
			newQuery1.getNotThrough().addAll(singleFlow.getNotThrough());
		
		newQuery1.getTo().addAll(singleFlow.getThrough());
		newQuery2.getFrom().addAll(singleFlow.getThrough());
		
		if (singleFlow.getNotThrough() != null)
			newQuery2.getNotThrough().addAll(singleFlow.getNotThrough());
		
		newQuery2.getTo().addAll(singleFlow.getTo());
		
		List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> 
			originalReachMap = new ArrayList<>(),
			reachMap1 = analyzePlainFlow(newQuery1), 
			reachMap2 = analyzePlainFlow(newQuery2);
		
		if (reachMap1.size() != 0 && reachMap2.size() != 0) {
			for (DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>
					sourcePair : reachMap1) {
				
				for (DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>> 
						sinkPair : reachMap2) {
					
					if (isSourceAndSinkMatching(sourcePair.getSecond(), sinkPair.getSecond())) {
						SameTypedPair<LocationDetails> stichedPair = 
								stitchSourceAndSink(sourcePair.getSecond(), sinkPair.getSecond());
						
						originalReachMap.add(new 
								DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>
									(singleFlow, stichedPair));
					}
				}
				
			}			
		}
		
		return originalReachMap;
	}
		
	private List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> 
		analyzeInternal(Boomerang boomerang, TaintFlowQueryImpl flowQuery, Set<ForwardQuery> sources,
			Set<BackwardQuery> sinks) {
		
		List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> reachMap = 
				new ArrayList<>();
		
		if (sources.size() != 0 && sinks.size() != 0) {
			
			Map<ForwardQuery, ForwardBoomerangResults<Weight.NoWeight>> forwardResults = new HashMap<>();			
			sources.forEach(source -> forwardResults.put(source, boomerang.solve(source)));
			reachMap = getReachingPairs(boomerang, flowQuery, sinks, forwardResults);	
			
		}	
		
		return reachMap;
	}
	
	private List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> 
		getReachingPairs(Boomerang boomerang, TaintFlowQueryImpl flowQuery, Set<BackwardQuery> sinks,
				Map<ForwardQuery, ForwardBoomerangResults<Weight.NoWeight>> sourceResults) {
		
		List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> reachMap = 
				new ArrayList<>();
		
		for (Entry<ForwardQuery,ForwardBoomerangResults<Weight.NoWeight>> sourceEntry 
				: sourceResults.entrySet()) {
			
			for (BackwardQuery sink : sinks) {
				
				if (isValidPath(sourceEntry.getValue(), sink)) {
					reachMap.add(new DifferentTypedPair<>(
							flowQuery, getLocationDetailsPair(flowQuery, sourceEntry.getKey(), sink)));
				}
				
			}
		}
		
		return reachMap;
	}
	
	private boolean isValidPath(ForwardBoomerangResults<Weight.NoWeight> sourceResult, 
			BackwardQuery sink) {
		
		Table<Edge, Val, Weight.NoWeight> table = sourceResult.asStatementValWeightTable();
		
		Edge sinkEdge = sink.cfgEdge();
		Val sinkValue = sink.var();
		
		return table.contains(sinkEdge, sinkValue);
		
	}
		
	private SameTypedPair<LocationDetails> getLocationDetailsPair(TaintFlowQueryImpl flowQuery,
			Query start, Query end){
		
		LocationDetails startDetails = new LocationDetails();
		startDetails.setSourceClassName(start.cfgEdge().getMethod().getDeclaringClass().getName());
		startDetails.setMethodSignature(start.cfgEdge().getMethod().getSubSignature());
		
		// TODO: Confirm that the destination is always Y.		
		startDetails.setUsageStartLineNumber(start.cfgEdge().getY().getStartLineNumber());
		startDetails.setUsageEndLineNumber(start.cfgEdge().getY().getEndLineNumber());
		startDetails.setUsageStartColumnNumber(start.cfgEdge().getY().getStartColumnNumber());	
		startDetails.setUsageEndColumnNumber(start.cfgEdge().getY().getEndColumnNumber());	
		
		startDetails.setUsageMethodSignature(start.cfgEdge().getY().getMethod().getSubSignature());
		startDetails.setUsageClassName(start.cfgEdge().getY().getMethod().getDeclaringClass().getName());
		startDetails.setType(LocationType.Source);
		
		LocationDetails endDetails = new LocationDetails();
		endDetails.setSourceClassName(end.cfgEdge().getMethod().getDeclaringClass().getName());
		endDetails.setMethodSignature(end.cfgEdge().getMethod().getSubSignature());
		
		// TODO: Confirm that the destination is always Y.	
		endDetails.setUsageStartLineNumber(end.cfgEdge().getY().getStartLineNumber());
		endDetails.setUsageEndLineNumber(end.cfgEdge().getY().getEndLineNumber());
		endDetails.setUsageStartColumnNumber(end.cfgEdge().getY().getStartColumnNumber());
		endDetails.setUsageEndColumnNumber(end.cfgEdge().getY().getEndColumnNumber());
		
		endDetails.setUsageMethodSignature(end.cfgEdge().getY().getMethod().getSubSignature());
		endDetails.setUsageClassName(end.cfgEdge().getY().getMethod().getDeclaringClass().getName());
		endDetails.setType(LocationType.Sink);		
		
		return new SameTypedPair<LocationDetails>(startDetails, endDetails);
		
	}
		
	private AnalysisScope getAnalysisScope(TaintFlowQuery taintFlow) {
		return new SingleFlowAnalysisScope(taintFlow, this.sootCallGraph);
	}
	
	private Boomerang getBoomerang(AnalysisScope analysisScope) {
		return new SingleFlowBoomerang(analysisScope, this.sootCallGraph, new TaintAnalysisOptions());
	}

	private List<Method> getSanitizers(TaintFlowQuery partFlow) {
		
		List<Method> sanitizers = new ArrayList<Method>();	
		
		if (partFlow.getNotThrough() != null)
			partFlow.getNotThrough().forEach(y -> sanitizers.add((Method)y));
		
		return sanitizers;
	}
	
	private Seeds computeSeeds(AnalysisScope analysisScope) {
		
		Set<ForwardQuery> sources = Sets.newHashSet();
		Set<BackwardQuery> sinks = Sets.newHashSet();
		Collection<Query> computeSeeds = analysisScope.computeSeeds();
		
		for (Query q : computeSeeds) {
			if (q instanceof BackwardQuery) {
				sinks.add((BackwardQuery) q);
			} else if (q instanceof ForwardQuery) {
				sources.add((ForwardQuery) q);
			}
		} 
		
		return new Seeds(sources, sinks);
	}
	
	private Map<SootMethod, Body> setEmptySootBodies(List<Method> methods){
		Map<SootMethod, Body> oldBodies = new HashMap<>();
		
		for (Method method : methods) {
			SootMethod sootMethod = Utility.getSootMethod(method);
			if (sootMethod != null) {
				Body body = sootMethod.getActiveBody();
				if (body != null) {
					oldBodies.put(sootMethod, body);
				}
				JimpleBody replacementBody = new JimpleBody();
				replacementBody.setMethod(sootMethod);
				replacementBody.getUnits().add(new JNopStmt());
				replacementBody.insertIdentityStmts();
				sootMethod.setActiveBody(replacementBody);
			}
		}	
		
		return oldBodies;
	}
	
	private boolean isPropogatorless(TaintFlowQueryImpl singleFlow) {
		return singleFlow.getThrough() == null || singleFlow.getThrough().size() == 0;
	}
	
	private boolean isSourceAndSinkMatching(SameTypedPair<LocationDetails> sourcePair, 
			SameTypedPair<LocationDetails> sinkPair) {
		
		if (!sourcePair.getSecond().getUsageClassName().equals(
				sinkPair.getFirst().getUsageClassName()))
			return false;
		
		if (!sourcePair.getSecond().getUsageMethodSignature().equals(
				sinkPair.getFirst().getUsageMethodSignature()))
			return false;
		
		if (!sourcePair.getSecond().getSourceClassName().equals(
				sinkPair.getFirst().getSourceClassName()))
			return false;
		
		if (!sourcePair.getSecond().getMethodSignature().equals(
				sinkPair.getFirst().getMethodSignature()))
			return false;
		
		if (sourcePair.getSecond().getUsageStartLineNumber() != 
				sinkPair.getFirst().getUsageStartLineNumber())
			return false;
		
		if (sourcePair.getSecond().getUsageEndLineNumber() != 
				sinkPair.getFirst().getUsageEndLineNumber())
			return false;
		
		if (sourcePair.getSecond().getUsageStartColumnNumber() != 
				sinkPair.getFirst().getUsageStartColumnNumber())
			return false;
		
		if (sourcePair.getSecond().getUsageEndColumnNumber() != 
				sinkPair.getFirst().getUsageEndColumnNumber())
			return false;
		
		return true;
	}
	
	private SameTypedPair<LocationDetails>  stitchSourceAndSink(
			SameTypedPair<LocationDetails> sourcePair, SameTypedPair<LocationDetails> sinkPair) {
		return new SameTypedPair<>(sourcePair.getFirst(), sinkPair.getSecond());
	}
}