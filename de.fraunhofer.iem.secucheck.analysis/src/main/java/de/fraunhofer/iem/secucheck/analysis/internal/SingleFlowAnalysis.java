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
		
		for (TaintFlowQueryImpl flowQuery : getLogicalSubFlows(singleFlow)) {
			if (this.resultListener != null && this.resultListener.isCancelled()) {
				break;
			}
			SeedFactory<NoWeight> seedFactory = getSeedFactory(flowQuery);
			Boomerang boomerang = getBoomerang(seedFactory);
			Seeds seeds = computeSeeds(seedFactory);
			
			if (seeds.getSources().size() != 0 && seeds.getSinks().size() != 0) {
				List<Method> sanitizers = getSanitizers(flowQuery);
				Map<SootMethod, Body> oldMethodBodies = new HashMap<SootMethod, Body>();
				List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> reachMap =
						new ArrayList<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>>();
				try	{
					oldMethodBodies = setEmptySootBodies(sanitizers);
					reachMap = analyzeInternal(boomerang, flowQuery, seeds.getSources(),
							seeds.getSinks());
				} finally {
					oldMethodBodies.entrySet().forEach( entry ->
						entry.getKey().setActiveBody(entry.getValue()));
				}
				if (reachMap.size() == 0) {
					result.clear();
					break;
				}
				result.addQueryResultPairs(reachMap);
			}
		}
		return result;
	}
	
	private List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> analyzeInternal(Boomerang boomerang, 
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

	/* Each occurance of a propogator/desanitizer would break a single
	 * TaintFlow into two logical TaintFlows, this method generates 
	 * these TaintFlows. */
	private List<TaintFlowQueryImpl> getLogicalSubFlows(
			TaintFlowQueryImpl partialFlow) {
		List<TaintFlowQueryImpl> subFlows = new ArrayList<TaintFlowQueryImpl>();
		if (partialFlow.getThrough() == null || partialFlow.getThrough().size() == 0){
			subFlows.add(partialFlow);
			return subFlows;
		}
		
		for (MethodImpl propogator : partialFlow.getThrough()) {
			TaintFlowQueryImpl	newQuery1 = new TaintFlowQueryImpl(), 
							newQuery2 = new TaintFlowQueryImpl();
			newQuery1.getFrom().addAll(partialFlow.getFrom());
			
			if (partialFlow.getNotThrough() != null)
				newQuery1.getNotThrough().addAll(partialFlow.getNotThrough());
			
			newQuery1.getTo().add(propogator);
			newQuery2.getFrom().add(propogator);
			
			if (partialFlow.getNotThrough() != null)
				newQuery2.getNotThrough().addAll(partialFlow.getNotThrough());
			
			newQuery2.getTo().addAll(partialFlow.getTo());
			subFlows.add(newQuery1);
			subFlows.add(newQuery2);
		}
		
		return subFlows;
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
								flowQuery, getLocationdetailsPair(flowQuery, start, end)));
					} else if (start instanceof BackwardQuery) {
						reachMap.add(new DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>(
								flowQuery, getLocationdetailsPair(flowQuery, end, start)));
					}
				}
			}
		}
		return reachMap;
	}
	
	private SameTypedPair<LocationDetails> getLocationdetailsPair(TaintFlowQueryImpl flowQuery,
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
		
	private SeedFactory<NoWeight> getSeedFactory(TaintFlowQuery partialFlow) {
		Set<SootMethod> sourceMethods = new HashSet<SootMethod>();
		Set<SootMethod> sinkMethods = new HashSet<SootMethod>();
		
		return new SeedFactory<NoWeight>() {
			@Override
			protected Collection<? extends Query> generate(SootMethod method, Stmt u) {
				Set<Query> out = Sets.newHashSet();
				
				Collection<Value> sourceVariables = generateSourceVariables(partialFlow, method, u);
				sourceVariables.forEach(v -> 
					out.add(new ForwardQuery(new Statement(u, method), new Val(v, method))) );
				
				Collection<Value> sinkVariables = generatedSinkVariables(partialFlow, method, u);
				sinkVariables.forEach(v -> 
					out.add(new BackwardQuery(new Statement(u, method), new Val(v, method))));
				
				// Find source method	
				for (Method flowMethod : partialFlow.getFrom()) {
					if (method.toString().equals("<" + flowMethod.getSignature() + ">")) {
						sourceMethods.add(method);
					}
				}

				// Find target method				
				for (Method flowMethod : partialFlow.getTo()) {
					if (method.toString().equals("<" + flowMethod.getSignature() + ">")) {
						sinkMethods.add(method);
					}
				}
				return out;
			}
			
			@Override
			public ObservableICFG<Unit, SootMethod> icfg() { return SingleFlowAnalysis.this.icfg; }
		};
		
		// Note currently this is broken. See Ticket #10 on github.
		// https://github.com/secure-software-engineering/secucheck/issues/10

//		if (!sourceMethods.isEmpty()) {
//			taintReporter.markMethod(sourceMethods.iterator().next(), MarkerType.SOURCE_METHOD);
//		}
//		
//		if (!sinkMethods.isEmpty()) {
//			taintReporter.markMethod(sinkMethods.iterator().next(), MarkerType.SINK_METHOD);
//		}

	}
	
	private Boomerang getBoomerang(SeedFactory<NoWeight> seedFactory) {
		return new Boomerang(new TaintAnalysisOptions()) {
			@Override
			public ObservableICFG<Unit, SootMethod> icfg() {
				return SingleFlowAnalysis.this.icfg;
			}
			
			@Override
			public SeedFactory<NoWeight> getSeedFactory() {
				return seedFactory;
			}
		};
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
	
	protected Collection<Value> generateSourceVariables(TaintFlowQuery partialFlow, 
			SootMethod method, Stmt actualStatement) {
		
		for (Object object : partialFlow.getFrom()) {
			Method sourceMethod = (Method) object;
			String sourceSootSignature = "<" + sourceMethod.getSignature() + ">";
			Collection<Value> out = Sets.newHashSet();

			if (method.getSignature().equals(sourceSootSignature) && 
					actualStatement instanceof IdentityStmt) {
				
				IdentityStmt identity = (IdentityStmt) actualStatement;
				Value right = identity.getRightOp();
				if (right instanceof ParameterRef) {
					ParameterRef parameterRef = (ParameterRef) right;
					for (OutputParameter output : sourceMethod.getOutputParameters()) {
						int parameterIndex = output.getNumber();
						if (parameterRef.getIndex() == parameterIndex
								&& method.getParameterCount() >= parameterIndex) {
							out.add(identity.getLeftOp());
						}
					}
				}
				return out;

			} else if (actualStatement.containsInvokeExpr()
					&& actualStatement.toString().contains(sourceSootSignature)) {

				// taint the return value
				
				if (sourceMethod.getReturnValue() != null && actualStatement instanceof AssignStmt) {
					out.add(((AssignStmt) actualStatement).getLeftOp());
				} 
				
				for (OutputParameter output : sourceMethod.getOutputParameters()) {
					int parameterIndex =  output.getNumber();
					if (actualStatement.getInvokeExpr().getArgCount() >= parameterIndex) {
						out.add(actualStatement.getInvokeExpr().getArg(parameterIndex));
					}
				}
				
				// taint this object
				if (sourceMethod.isOutputThis() && actualStatement.getInvokeExpr() instanceof InstanceInvokeExpr) {
					InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) actualStatement.getInvokeExpr();
					out.add(instanceInvoke.getBase());
				}
				
				// // taint this object
				// if (this.flow.getSource().getSingleSource().getTvOut() != null
				// && actualStatement.getInvokeExpr() instanceof InstanceInvokeExpr) {
				// InstanceInvokeExpr instanceInvokeExpr = (InstanceInvokeExpr)
				// actualStatement.getInvokeExpr();
				// out.add(instanceInvokeExpr.getBase());
				// }
				return out;
			}

		}
	

//		if (this.flow.getSource().getValueSource() != null) // a single value source
//		{
//			// TODO:handle this
//		} 
		return Collections.emptySet();
	}

	protected Collection<Value> generatedSinkVariables(TaintFlowQuery partialFlow, 
			SootMethod method, Stmt actualStatement) {
		for (Object object : partialFlow.getTo()) {
			Method sourceMethod = (Method) object;
			String sourceSootSignature = "<" + sourceMethod.getSignature() + ">";
			Collection<Value> out = Sets.newHashSet();

			if (actualStatement.containsInvokeExpr() 
					&& actualStatement.toString().contains(sourceSootSignature)) {
				// taint the return value
				for (InputParameter input : sourceMethod.getInputParameters()) {
					int parameterIndex = input.getNumber();
					if (actualStatement.getInvokeExpr().getArgCount() >= parameterIndex) {
						out.add(actualStatement.getInvokeExpr().getArg(parameterIndex));
					}
				}
				
				// taint this object
				if (sourceMethod.isInputThis() && actualStatement.getInvokeExpr() instanceof InstanceInvokeExpr) {
					InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) actualStatement.getInvokeExpr();
					out.add(instanceInvoke.getBase());
				}
				
				// // taint this object
				// if (this.flow.getSource().getSingleSource().getTvOut() != null
				// && actualStatement.getInvokeExpr() instanceof InstanceInvokeExpr) {
				// InstanceInvokeExpr instanceInvokeExpr = (InstanceInvokeExpr)
				// actualStatement.getInvokeExpr();
				// out.add(instanceInvokeExpr.getBase());
				// }
				return out;
			}

		}
		// TODO: re-check the sink structure!!
		return Collections.emptySet();
	}	

	private boolean isValidPath(Boomerang boomerang, Query start, Query end) {
		// Quick check: Is the "end" included in the Table at all?
		Statement s = end.asNode().stmt();
		Val v = end.asNode().fact();
		Table<Statement, Val, NoWeight> results = boomerang.getResults(start);
		return results.get(s, v) == null ? false : true;
	}
}