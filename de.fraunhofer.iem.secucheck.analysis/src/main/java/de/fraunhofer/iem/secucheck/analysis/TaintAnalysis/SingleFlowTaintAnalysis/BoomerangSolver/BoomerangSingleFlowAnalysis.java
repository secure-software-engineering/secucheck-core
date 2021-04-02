package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver;

import java.util.*;
import java.util.Map.Entry;

import boomerang.*;
import boomerang.guided.DemandDrivenGuidedAnalysis;
import boomerang.scene.*;
import boomerang.scene.jimple.JimpleVal;
import com.google.common.collect.Sets;
import com.google.common.collect.Table;

import boomerang.results.ForwardBoomerangResults;
import boomerang.scene.ControlFlowGraph.Edge;
import boomerang.scene.jimple.BoomerangPretransformer;
import boomerang.scene.jimple.JimpleStatement;
import boomerang.scene.jimple.SootCallGraph;
import de.fraunhofer.iem.secucheck.analysis.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.*;
import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.SameTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.LocationDetails;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.LocationType;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.TaintFlowQueryResult;
import soot.Body;
import soot.PackManager;
import soot.SceneTransformer;
import soot.SootMethod;
import soot.Transform;
import soot.jimple.IdentityStmt;
import soot.jimple.JimpleBody;
import soot.jimple.ParameterRef;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JNopStmt;

import wpds.impl.Weight;

public class BoomerangSingleFlowAnalysis implements SingleFlowAnalysis {

    private final TaintFlowQueryImpl singleFlow;
    private final SecucheckAnalysisConfiguration configuration;

    private final TaintFlowQueryResult result;

    public BoomerangSingleFlowAnalysis(TaintFlowQueryImpl singleFlow, SecucheckAnalysisConfiguration configuration) {
        this.singleFlow = singleFlow;
        this.configuration = configuration;
        this.result = new TaintFlowQueryResult();
    }

    @Override
    public TaintFlowQueryResult run() throws Exception {

        String classPath = Utility.getCombinedSootClassPath(this.configuration.getOs(),
                this.configuration.getApplicationClassPath(), this.configuration.getSootClassPathJars());

        Utility.initializeSootWithEntryPoints(classPath, this.configuration.getAnalysisEntryPoints());
        Utility.loadAllParticipantMethods(singleFlow);

        Transform transform = new Transform("wjtp.ifds", createAnalysisTransformer());
        PackManager.v().getPack("wjtp").add(transform);
        PackManager.v().getPack("cg").apply();

        BoomerangPretransformer.v().apply();
        PackManager.v().getPack("wjtp").apply();
        BoomerangPretransformer.v().reset();
        return this.result;
    }

    private SceneTransformer createAnalysisTransformer() throws Exception {
        return new SceneTransformer() {
            protected void internalTransform(String phaseName, @SuppressWarnings("rawtypes") Map options) {
                executeAnalysis();
            }
        };
    }

    private void executeAnalysis() {
        // Propogator-less execution.
        if (isPropogatorless(this.singleFlow)) {
            result.addQueryResultPairs(analyzePlainFlow(singleFlow));
        } else {
            result.addQueryResultPairs(analyzePropogatorFlow(singleFlow));
        }
    }

    public List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>>
    analyzePlainFlow(TaintFlowQueryImpl singleFlow) {

        List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>>
                reachMap = new ArrayList<>();

        SootCallGraph callGraph = new SootCallGraph();
        AnalysisScope analysisScope = getAnalysisScope(singleFlow, callGraph);
        Boomerang boomerang = getBoomerang(analysisScope, callGraph);
        Seeds seeds = computeSeeds(analysisScope);

        if (seeds.getSources().size() != 0 && seeds.getSinks().size() != 0) {

            List<Method> sanitizers = getSanitizers(singleFlow);
            Map<SootMethod, Body> oldMethodBodies = new HashMap<SootMethod, Body>();

            try {
                oldMethodBodies = setEmptySootBodies(sanitizers);
                reachMap = analyzeInternal(boomerang, singleFlow, seeds.getSources(),
                        seeds.getSinks());
            } finally {
                oldMethodBodies.entrySet().forEach(entry ->
                        entry.getKey().setActiveBody(entry.getValue()));
            }
        }

        return reachMap;
    }

    public List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>>
    analyzePropogatorFlow(TaintFlowQueryImpl singleFlow) {

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

		/*	Specification specification =
					Specification.create(
							"<ON{B}java.lang.StringBuilder: java.lang.StringBuilder append(GO{B}java.lang.String)>",
							"<ON{F}java.lang.StringBuilder: java.lang.StringBuilder append(GO{B}java.lang.String)>",
							"<ON{F}java.lang.StringBuilder: GO{F}java.lang.StringBuilder append(java.lang.String)>",
							"<GO{B}java.lang.StringBuilder: ON{B}java.lang.String toString()>");
*/
            //	for (Query source : sources) {
            DemandDrivenGuidedAnalysis demandDrivenGuidedAnalysis = new DemandDrivenGuidedAnalysis(
                    new BoomerangGPHandler(),
                    new MyDefaultBoomerangOptions(),
                    new CustomDataFlowScope());

            QueryGraph<Weight.NoWeight> queryGraph = demandDrivenGuidedAnalysis.run((Query) sources.toArray()[0]);

            Set<Query> queries = queryGraph.getNodes();

            System.out.println("Criticaöllll = " + queryGraph.getNodes().size() + " ---- " + queryGraph);

            for (Query query : queries) {
                System.out.println(query);
            }
            //	}
        }

        return reachMap;
    }

    private List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>>
    getReachingPairs(Boomerang boomerang, TaintFlowQueryImpl flowQuery, Set<BackwardQuery> sinks,
                     Map<ForwardQuery, ForwardBoomerangResults<Weight.NoWeight>> sourceResults) {

        List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> reachMap =
                new ArrayList<>();

        for (Entry<ForwardQuery, ForwardBoomerangResults<Weight.NoWeight>> sourceEntry
                : sourceResults.entrySet()) {

            for (BackwardQuery sink : sinks) {
                if (isValidPath(sourceEntry.getValue(), sink)) {
                    reachMap.add(new DifferentTypedPair<>(
                            flowQuery, getLocationDetailsPair(flowQuery, sourceEntry.getKey(), sink)));
                } //else {
                //reachMap.addAll(recursiveQuery(boomerang, sourceEntry, sinks, flowQuery));
                //}

            }
        }

        return reachMap;
    }

    ForwardQuery lastIterationQuery = null;

    private List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> recursiveQuery(Boomerang boomerang,
                                                                                                        Entry<ForwardQuery, ForwardBoomerangResults<Weight.NoWeight>> sourceEntry,
                                                                                                        Set<BackwardQuery> sinks,
                                                                                                        TaintFlowQueryImpl flowQuery) {

        ForwardQuery newQuery = getLastValue(sourceEntry.getValue().asStatementValWeightTable(), sourceEntry.getKey());

        if (lastIterationQuery != null && lastIterationQuery.toString().equals(newQuery.toString()))
            return Collections.emptyList();

        lastIterationQuery = newQuery;

        if (newQuery.var() == null || newQuery.cfgEdge() == null) {
            return Collections.emptyList();
        }

        BoomerangPretransformer.v().reset();
        return analyzeInternal(boomerang, flowQuery, new HashSet() {{
            add(newQuery);
        }}, sinks);

    }

    private ForwardQuery getLastValue(Table<Edge, Val, Weight.NoWeight> table, ForwardQuery forwardQuery) {
        Edge edge = null, tmp1 = null;
        Val val = null;
        Statement stmt = null, tmp3 = null;

        System.out.println("Size = " + table.cellSet().size());

        int size = table.cellSet().size() - 1;

        Table.Cell<Edge, Val, Weight.NoWeight> cell = null;


        while (true) {
            if (size < 0)
                break;

            cell = (Table.Cell<Edge, Val, Weight.NoWeight>) table.cellSet().toArray()[size--];

            if (cell.getRowKey().getTarget().toString().contains("append")) {
                tmp1 = cell.getRowKey();
                edge = cell.getRowKey();

                tmp3 = cell.getRowKey().getTarget();
                stmt = cell.getRowKey().getTarget();
//                System.out.println("CCheck = " + edge + "\n" + stmt);
                JimpleStatement jimpleStament = (JimpleStatement) stmt;

                if (jimpleStament.getDelegate() instanceof JAssignStmt) {
                    JAssignStmt identityStmt = (JAssignStmt) jimpleStament.getDelegate();
                    val = new JimpleVal(identityStmt.getLeftOp(), cell.getRowKey().getTarget().getMethod());
                } else {
                    val = cell.getRowKey().getTarget().getInvokeExpr().getBase();
                    System.err.println("Its not JAssignStmt statement. Please check = " + jimpleStament.getDelegate().getClass().getCanonicalName()
                            + " --- \n" + jimpleStament);
                }

                break;
            }
        }


        if (edge == null || val == null || stmt == null) {
            System.out.println("NULL CCCCCCCCRRRRRITICAL = " + tmp1);
            System.out.println("val");
            System.out.println(tmp3);
        } else {
            System.out.println("CCCCCCCCRRRRRITICAL = " + edge);
            System.out.println(val);
            System.out.println(stmt);
        }

        return new ForwardQuery(edge, new AllocVal(
                val,
                stmt,
                val));
    }

    private ForwardQuery getLastValue1(Table<Edge, Val, Weight.NoWeight> table, ForwardQuery forwardQuery) {
        Edge edge = null, tmp1 = null;
        Val val = null;
        Statement stmt = null, tmp3 = null;

        System.out.println("Size = " + table.cellSet().size());
        for (Table.Cell<Edge, Val, Weight.NoWeight> cell : table.cellSet()) {

            tmp1 = cell.getRowKey();

            tmp3 = cell.getRowKey().getTarget();
            if (cell.getColumnKey().toString().equals(forwardQuery.var().toString())) {
                if (!cell.getRowKey().toString().equals(forwardQuery.cfgEdge().toString())) {
                    edge = cell.getRowKey();

                    stmt = cell.getRowKey().getTarget();
                    JimpleStatement jimpleStament = (JimpleStatement) stmt;

                    if (jimpleStament.getDelegate() instanceof JAssignStmt) {
                        JAssignStmt identityStmt = (JAssignStmt) jimpleStament.getDelegate();
                        val = new JimpleVal(identityStmt.getLeftOp(), cell.getRowKey().getTarget().getMethod());
                    } else {
                        System.err.println("Its not JAssignStmt statement. Please check = " + jimpleStament.getDelegate().getClass().getCanonicalName()
                                + " --- \n" + jimpleStament);
                    }
                }
            }
        }

        if (edge == null || val == null || stmt == null) {
            System.out.println("NULL CCCCCCCCRRRRRITICAL = " + tmp1);
            System.out.println("val");
            System.out.println(tmp3);
        } else {
            System.out.println("CCCCCCCCRRRRRITICAL = " + edge);
            System.out.println(val);
            System.out.println(stmt);
        }

        return new ForwardQuery(edge, new AllocVal(
                val,
                stmt,
                val));
    }

    private boolean isValidPath(ForwardBoomerangResults<Weight.NoWeight> sourceResult,
                                BackwardQuery sink) {

        Table<Edge, Val, Weight.NoWeight> table = sourceResult.asStatementValWeightTable();
/*
        System.out.println("°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°");
        for (Table.Cell<Edge, Val, Weight.NoWeight> cell : table.cellSet()) {
            System.out.println("*******************************************");
            System.out.println("Column = " + cell.getColumnKey());
            System.out.println("Row = " + cell.getRowKey());
            System.out.println("Value = " + cell.getValue());
            System.out.println("*******************************************");
        }
        System.out.println("°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°");
*/
        Edge sinkEdge = sink.cfgEdge();
        Val sinkValue = sink.var();

        return table.contains(sinkEdge, sinkValue);

    }

    private SameTypedPair<LocationDetails> getLocationDetailsPair(TaintFlowQueryImpl flowQuery,
                                                                  Query start, Query end) {

        LocationDetails startDetails = new LocationDetails();
        startDetails.setSourceClassName(start.cfgEdge().getMethod().getDeclaringClass().getName());
        startDetails.setMethodSignature(start.cfgEdge().getMethod().getSubSignature());

        // When parameter is tainted.
        // Left and Right Op() methods don't work for IdentityStmt inside JimpleStatement.
        if (start.cfgEdge().getY().isIdentityStmt() && start.cfgEdge().getY() instanceof JimpleStatement) {
            JimpleStatement jimpleStament = (JimpleStatement) start.cfgEdge().getY();
            IdentityStmt identityStmt = (IdentityStmt) jimpleStament.getDelegate();
            if (identityStmt.getRightOp() instanceof ParameterRef) {
                SootMethod sootMethod = Utility.getSootMethod(start.cfgEdge().getY().getMethod());
                startDetails.setUsageStartLineNumber(sootMethod.getJavaSourceStartLineNumber());
                startDetails.setUsageEndLineNumber(-1);
                startDetails.setUsageStartColumnNumber(sootMethod.getJavaSourceStartColumnNumber());
                startDetails.setUsageEndColumnNumber(-1);
            }
        } else {
            startDetails.setUsageStartLineNumber(start.cfgEdge().getY().getStartLineNumber());
            startDetails.setUsageEndLineNumber(start.cfgEdge().getY().getEndLineNumber());
            startDetails.setUsageStartColumnNumber(start.cfgEdge().getY().getStartColumnNumber());
            startDetails.setUsageEndColumnNumber(start.cfgEdge().getY().getEndColumnNumber());
        }

        startDetails.setUsageMethodSignature(start.cfgEdge().getY().getMethod().getSubSignature());
        startDetails.setUsageClassName(start.cfgEdge().getY().getMethod().getDeclaringClass().getName());
        startDetails.setType(LocationType.Source);

        LocationDetails endDetails = new LocationDetails();
        endDetails.setSourceClassName(end.cfgEdge().getMethod().getDeclaringClass().getName());
        endDetails.setMethodSignature(end.cfgEdge().getMethod().getSubSignature());

        endDetails.setUsageStartLineNumber(end.cfgEdge().getY().getStartLineNumber());
        endDetails.setUsageEndLineNumber(end.cfgEdge().getY().getEndLineNumber());
        endDetails.setUsageStartColumnNumber(end.cfgEdge().getY().getStartColumnNumber());
        endDetails.setUsageEndColumnNumber(end.cfgEdge().getY().getEndColumnNumber());

        endDetails.setUsageMethodSignature(end.cfgEdge().getY().getMethod().getSubSignature());
        endDetails.setUsageClassName(end.cfgEdge().getY().getMethod().getDeclaringClass().getName());
        endDetails.setType(LocationType.Sink);

        return new SameTypedPair<LocationDetails>(startDetails, endDetails);

    }

    private AnalysisScope getAnalysisScope(TaintFlowQuery taintFlow, SootCallGraph callGraph) {
        return new SingleFlowAnalysisScope(taintFlow, callGraph);
    }

    private Boomerang getBoomerang(AnalysisScope analysisScope, SootCallGraph callGraph) {
        return new SingleFlowBoomerang(analysisScope, callGraph, new TaintAnalysisOptions());
    }

    private List<Method> getSanitizers(TaintFlowQuery partFlow) {

        List<Method> sanitizers = new ArrayList<Method>();

        if (partFlow.getNotThrough() != null)
            partFlow.getNotThrough().forEach(y -> sanitizers.add((Method) y));

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

        System.out.println("\n\n\nSources: " + sources.size());
        for (ForwardQuery forwardQuery : sources) {
            System.out.println(forwardQuery.var());
        }
/*
		System.out.println("\n\n\nSinks:");
		for (BackwardQuery backwardQuery : sinks) {
			System.out.println(backwardQuery.var().m().toString());
		}
*/
        return new Seeds(sources, sinks);
    }

    private Map<SootMethod, Body> setEmptySootBodies(List<Method> methods) {
        Map<SootMethod, Body> oldBodies = new HashMap<>();

        for (Method method : methods) {
            SootMethod sootMethod = Utility.getSootMethod(method);
            if (sootMethod != null && !sootMethod.isPhantom()) {
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

    private SameTypedPair<LocationDetails> stitchSourceAndSink(
            SameTypedPair<LocationDetails> sourcePair, SameTypedPair<LocationDetails> sinkPair) {
        return new SameTypedPair<>(sourcePair.getFirst(), sinkPair.getSecond());
    }
}