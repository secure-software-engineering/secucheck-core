package de.fraunhofer.iem.secucheck.analysis.internal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.Sets;
import com.google.common.collect.Table;

import boomerang.BackwardQuery;
import boomerang.Boomerang;
import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.callgraph.ObservableICFG;
import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import boomerang.seedfactory.SeedFactory;
import de.fraunhofer.iem.secucheck.analysis.Analysis;
import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.Pair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.SameTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.ReturnValue;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.LocationDetails;
import de.fraunhofer.iem.secucheck.analysis.result.LocationType;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;
import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.IdentityStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.JimpleBody;
import soot.jimple.ParameterRef;
import soot.jimple.Stmt;
import soot.jimple.internal.JNopStmt;
import soot.tagkit.Host;
import soot.tagkit.PositionTag;
import soot.tagkit.AbstractHost;
import wpds.impl.Weight.NoWeight;

class SingleFlowAnalysis implements Analysis {

	private final TaintFlowQueryImpl singleFlow;
	private final ObservableICFG<Unit, SootMethod> icfg;
	private final AnalysisResultListener resultListener;
	
	public SingleFlowAnalysis(TaintFlowQueryImpl singleFlow,
			ObservableICFG<Unit, SootMethod> icfg, 
			AnalysisResultListener resultListener) {
		this.singleFlow = singleFlow;
		this.icfg = icfg;
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
			reachMap = new ArrayList<DifferentTypedPair<TaintFlowQueryImpl,SameTypedPair<LocationDetails>>>();
		
		SeedFactory<NoWeight> seedFactory = getSeedFactory(singleFlow);
		Boomerang boomerang = getBoomerang(seedFactory);
		Seeds seeds = computeSeeds(seedFactory);
		
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
			originalReachMap = 
				new ArrayList<DifferentTypedPair<TaintFlowQueryImpl,SameTypedPair<LocationDetails>>>(),
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
		analyzeInternal(Boomerang boomerang, 
			TaintFlowQueryImpl partialFlow, Set<ForwardQuery> sources,
			Set<BackwardQuery> sinks) {
		
		List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> reachMap = 
				new ArrayList<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>>();
		
		if (sources.size() != 0 && sinks.size() != 0) {
			// Found more sinks than sources, running forward analysis
			if (sources.size() <= sinks.size()) {
				sources.forEach(source -> boomerang.solve(source));
				reachMap = getReachingPairs(boomerang, partialFlow, sources, sinks);
			} else {
				// Found less sinks than sources, running backward analysis
				sinks.forEach(sink -> boomerang.solve(sink));
				reachMap = getReachingPairs(boomerang, partialFlow, sinks, sources);
			}
		}				
		return reachMap;
	}
	
	private List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> 
		getReachingPairs(Boomerang boomerang, TaintFlowQueryImpl flowQuery, Set<? extends Query> queries,
			Set<? extends Query> reachable) {
		
		List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> reachMap = 
				new ArrayList<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>>();
		
		for (Query start : queries) {
			for (Query end : reachable) {
				if (isValidPath(boomerang, start, end)) {
					if (start instanceof ForwardQuery) {
						reachMap.add(new DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>(
								flowQuery, getLocationDetailsPair(flowQuery, start, end)));
					} else if (start instanceof BackwardQuery) {
						reachMap.add(new DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>(
								flowQuery, getLocationDetailsPair(flowQuery, end, start)));
					}
				}
			}
		}
		return reachMap;
	}
	
	private SameTypedPair<LocationDetails> getLocationDetailsPair(TaintFlowQueryImpl flowQuery,
			Query start, Query end){
		
		LocationDetails startDetails = new LocationDetails();
		SootMethod sourceMethodDefinition = Utility.findSourceMethodDefinition(flowQuery, start.stmt().getMethod(),
				start.stmt().getUnit().get());
		startDetails.setSourceClassName(sourceMethodDefinition.getDeclaringClass().getName());
		startDetails.setMethodSignature(sourceMethodDefinition.getSignature());
		
		AbstractHost sourceHost = (AbstractHost) start.asNode().stmt().getUnit().get();
		startDetails.setUsageLineNumber(sourceHost.getJavaSourceStartLineNumber());
		startDetails.setUsageColumnNumber(sourceHost.getJavaSourceStartColumnNumber());
		startDetails.setUsageMethodSignature(start.stmt().getMethod().getSignature());
		startDetails.setUsageClassName(start.stmt().getMethod().getDeclaringClass().getName());
		startDetails.setType(LocationType.Source);
		
		LocationDetails endDetails = new LocationDetails();
		SootMethod sinkMethodDefinition = Utility.findSinkMethodDefinition(flowQuery, end.stmt().getMethod(),
				end.stmt().getUnit().get());
		endDetails.setSourceClassName(sinkMethodDefinition.getDeclaringClass().getName());
		endDetails.setMethodSignature(sinkMethodDefinition.getSignature());
		
		AbstractHost sinkHost = (AbstractHost) end.asNode().stmt().getUnit().get();
		endDetails.setUsageLineNumber(sinkHost.getJavaSourceStartLineNumber());
		endDetails.setUsageColumnNumber(sinkHost.getJavaSourceStartColumnNumber());
		endDetails.setUsageMethodSignature(end.stmt().getMethod().getSignature());
		endDetails.setUsageClassName(end.stmt().getMethod().getDeclaringClass().getName());
		endDetails.setType(LocationType.Sink);		
		
		return new SameTypedPair<LocationDetails>(startDetails, endDetails);
	}
		
	private SeedFactory<NoWeight> getSeedFactory(TaintFlowQuery taintFlow) {
		return new SingleFlowSeedFactory(taintFlow, this.icfg);
	}
	
	private Boomerang getBoomerang(SeedFactory<NoWeight> seedFactory) {
		return new SingleFlowBoomerang(seedFactory, this.icfg, new TaintAnalysisOptions());
	}

	private List<Method> getSanitizers(TaintFlowQuery partFlow) {
		List<Method> sanitizers = new ArrayList<Method>();	
		if (partFlow.getNotThrough() != null)
			partFlow.getNotThrough().forEach(y -> sanitizers.add((Method)y));
		return sanitizers;
	}
	
	private Seeds computeSeeds(SeedFactory<NoWeight> seedFactory) {
		Set<ForwardQuery> sources = Sets.newHashSet();
		Set<BackwardQuery> sinks = Sets.newHashSet();
		Collection<Query> computeSeeds = seedFactory.computeSeeds();
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
		Map<SootMethod, Body> oldBodies = new HashMap<SootMethod, Body>();
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
		
		if (sourcePair.getSecond().getUsageLineNumber() != 
				sinkPair.getFirst().getUsageLineNumber())
			return false;
		
		if (sourcePair.getSecond().getUsageColumnNumber() != 
				sinkPair.getFirst().getUsageColumnNumber())
			return false;
		
		return true;
	}
	
	private SameTypedPair<LocationDetails>  stitchSourceAndSink(
			SameTypedPair<LocationDetails> sourcePair, SameTypedPair<LocationDetails> sinkPair) {
		SameTypedPair<LocationDetails> stichedPair = 
				new SameTypedPair<>(sourcePair.getFirst(), sinkPair.getSecond());
		return stichedPair;
	}
	
	private boolean isValidPath(Boomerang boomerang, Query start, Query end) {
		// Quick check: Is the "end" included in the Table at all?
		Statement s = end.asNode().stmt();
		Val v = end.asNode().fact();
		Table<Statement, Val, NoWeight> results = boomerang.getResults(start);
		return results.get(s, v) == null ? false : true;
	}
}