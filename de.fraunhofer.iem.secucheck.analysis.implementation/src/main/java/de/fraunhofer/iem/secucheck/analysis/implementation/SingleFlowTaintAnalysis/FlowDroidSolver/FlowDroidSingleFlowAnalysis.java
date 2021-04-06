package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.FlowDroidSolver;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis.SingleFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.configuration.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.Utility;
import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.SameTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlow;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;
import de.fraunhofer.iem.secucheck.analysis.result.LocationDetails;
import de.fraunhofer.iem.secucheck.analysis.result.LocationType;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;
import soot.Body;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.JimpleBody;
import soot.jimple.infoflow.Infoflow;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.config.IInfoflowConfig;
import soot.jimple.infoflow.entryPointCreators.DefaultEntryPointCreator;
import soot.jimple.infoflow.results.DataFlowResult;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.results.ResultSourceInfo;
import soot.jimple.internal.JNopStmt;
import soot.options.Options;

public class FlowDroidSingleFlowAnalysis implements SingleFlowAnalysis {

    private final TaintFlowImpl singleFlow;
    private final SecucheckAnalysisConfiguration configuration;

    private final TaintFlowQueryResult result;

    public FlowDroidSingleFlowAnalysis(TaintFlowImpl singleFlow, SecucheckAnalysisConfiguration configuration) {
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

        List<String> entryMethods = getCanonicalEntryMethodSignatures(configuration.getAnalysisEntryPoints());
        DefaultEntryPointCreator entryPointCreator = new DefaultEntryPointCreator(entryMethods);
        Infoflow infoFlow = getInfoFlow();

        if (isPropogatorless(this.singleFlow)) {
            result.addQueryResultPairs(analyzePlainFlow(singleFlow, infoFlow, entryPointCreator, this.configuration));
        } else {
            result.addQueryResultPairs(analyzePropogatorFlow(singleFlow, infoFlow, entryPointCreator, this.configuration));
        }
        return this.result;
    }

    public List<DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>>
    analyzePlainFlow(TaintFlowImpl singleFlow, Infoflow infoFlow,
                     DefaultEntryPointCreator entryPointCreator, SecucheckAnalysisConfiguration configuration) {

        List<DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>>
                reachMap = new ArrayList<>();

        List<String> sources = getCanonicalMethodSignatures(singleFlow.getFrom());
        List<String> sinks = getCanonicalMethodSignatures(singleFlow.getTo());

        List<Method> sanitizers = getSanitizers(singleFlow);
        Map<SootMethod, Body> oldMethodBodies = setEmptySootBodies(sanitizers);

        try {
            infoFlow.computeInfoflow(configuration.getApplicationClassPath(),
                    configuration.getSootClassPathJars(), entryPointCreator, sources, sinks);
        } finally {
            oldMethodBodies.entrySet().forEach(entry ->
                    entry.getKey().setActiveBody(entry.getValue()));
        }

        if (infoFlow.isResultAvailable()) {
            InfoflowResults map = infoFlow.getResults();
            if (map.size() > 0) {
                for (DataFlowResult dataFlowResult : map.getResultSet()) {
                    SameTypedPair<LocationDetails> locationPair = getLocationDetailsPair(singleFlow, dataFlowResult);
                    reachMap.add(new DifferentTypedPair<>(singleFlow, locationPair));
                }
            }
        }

        return reachMap;
    }

    public List<DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>>
    analyzePropogatorFlow(TaintFlowImpl singleFlow, Infoflow infoFlow,
                          DefaultEntryPointCreator entryPointCreator, SecucheckAnalysisConfiguration configuration) {

        /* Each occurance of a propogator/desanitizer would break a single
         * TaintFlow into two logical TaintFlows, this generates
         * these TaintFlows. */

        TaintFlowImpl newQuery1 = new TaintFlowImpl(),
                newQuery2 = new TaintFlowImpl();

        newQuery1.getFrom().addAll(singleFlow.getFrom());

        if (singleFlow.getNotThrough() != null)
            newQuery1.getNotThrough().addAll(singleFlow.getNotThrough());

        newQuery1.getTo().addAll(singleFlow.getThrough());
        newQuery2.getFrom().addAll(singleFlow.getThrough());

        if (singleFlow.getNotThrough() != null)
            newQuery2.getNotThrough().addAll(singleFlow.getNotThrough());

        newQuery2.getTo().addAll(singleFlow.getTo());

        List<DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>>
                originalReachMap = new ArrayList<>(),
                reachMap1 = analyzePlainFlow(newQuery1, infoFlow, entryPointCreator, configuration),
                reachMap2 = analyzePlainFlow(newQuery2, infoFlow, entryPointCreator, configuration);

        if (reachMap1.size() != 0 && reachMap2.size() != 0) {
            for (DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>
                    sourcePair : reachMap1) {

                for (DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>
                        sinkPair : reachMap2) {

                    if (isSourceAndSinkMatching(sourcePair.getSecond(), sinkPair.getSecond())) {
                        SameTypedPair<LocationDetails> stichedPair =
                                stitchSourceAndSink(sourcePair.getSecond(), sinkPair.getSecond());

                        originalReachMap.add(new
                                DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>
                                (singleFlow, stichedPair));
                    }
                }

            }
        }

        return originalReachMap;
    }


    private static List<String> getCanonicalEntryMethodSignatures(List<EntryPoint> entryPoints) {
        List<String> methodNames = new ArrayList<>();
        for (EntryPoint entryPoint : entryPoints) {
            // We are not supposed to deal with Soot explicitly for the case of InfoFlow solver.
            // So, the we will rely on explicitly specified entry-points.
            SootClass sootClass = Scene.v().forceResolve(entryPoint.getCanonicalClassName(), SootClass.BODIES);
            sootClass.setApplicationClass();
            if (entryPoint.isAllMethods()) {
                sootClass.getMethods().forEach(method -> methodNames.add(method.getSignature()));
            } else {
                entryPoint.getMethods().forEach(method -> methodNames.add(method));
            }
        }
        return methodNames;
    }

    private static List<String> getCanonicalMethodSignatures(List<MethodImpl> methodSpecs) {
        List<String> methodNames = new ArrayList<>();
        methodSpecs.forEach(
                method -> methodNames.add(Utility.wrapInAngularBrackets(method.getSignature())));
        return methodNames;
    }

    private static Infoflow getInfoFlow() {
        Infoflow infoFlow = new Infoflow();
        infoFlow.setSootConfig(new IInfoflowConfig() {

            @Override
            public void setSootOptions(Options options, InfoflowConfiguration config) {
                // TODO: set included packages.
                // options.set_include(includeList);
                options.set_exclude(Utility.excludedPackages());
                options.set_output_format(Options.output_format_none);
            }
        });
        infoFlow.getConfig().setInspectSinks(false);
        return infoFlow;
    }

    private boolean isPropogatorless(TaintFlowImpl singleFlow) {
        return singleFlow.getThrough() == null || singleFlow.getThrough().size() == 0;
    }

    private List<Method> getSanitizers(TaintFlow partFlow) {
        List<Method> sanitizers = new ArrayList<Method>();

        if (partFlow.getNotThrough() != null)
            partFlow.getNotThrough().forEach(y -> sanitizers.add((Method) y));

        return sanitizers;
    }

    private Map<SootMethod, Body> setEmptySootBodies(List<Method> methods) {
        Map<SootMethod, Body> oldBodies = new HashMap<>();

        for (Method method : methods) {
            SootMethod sootMethod = Utility.getSootMethod(method);
            if (sootMethod != null && sootMethod.hasActiveBody() && !sootMethod.isPhantom()) {
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

    private SameTypedPair<LocationDetails> getLocationDetailsPair(TaintFlowImpl singleFlow,
                                                                  DataFlowResult dataFlowResult) {

        ResultSourceInfo sourceInfo = dataFlowResult.getSource();

        LocationDetails startDetails = new LocationDetails();
        startDetails.setSourceClassName(sourceInfo.getStmt().getInvokeExpr().getMethodRef().getDeclaringClass().getName());
        startDetails.setMethodSignature(sourceInfo.getStmt().getInvokeExpr().getMethodRef().getSubSignature().getString());


        startDetails.setUsageStartLineNumber(sourceInfo.getStmt().getJavaSourceStartLineNumber());
        startDetails.setUsageEndLineNumber(-1);
        startDetails.setUsageStartColumnNumber(sourceInfo.getStmt().getJavaSourceStartColumnNumber());
        startDetails.setUsageEndColumnNumber(-1);

        // TODO: Not visible in the new Soot version.
        startDetails.setUsageMethodSignature(sourceInfo.getStmt().getInvokeExpr().getMethod().getSubSignature());
        startDetails.setUsageClassName(sourceInfo.getStmt().getInvokeExpr().getMethod().getDeclaringClass().getName());
        startDetails.setType(LocationType.Source);

        ResultSinkInfo sinkInfo = dataFlowResult.getSink();

        LocationDetails endDetails = new LocationDetails();
        // TODO: Not visible in the new Soot version.
        endDetails.setSourceClassName(sinkInfo.getStmt().getInvokeExpr().getMethodRef().getDeclaringClass().getName());
        endDetails.setMethodSignature(sinkInfo.getStmt().getInvokeExpr().getMethodRef().getSubSignature().getString());

        endDetails.setUsageStartLineNumber(sinkInfo.getStmt().getJavaSourceStartLineNumber());
        endDetails.setUsageEndLineNumber(-1);
        endDetails.setUsageStartColumnNumber(sinkInfo.getStmt().getJavaSourceStartColumnNumber());
        endDetails.setUsageEndColumnNumber(-1);

        // TODO: Not visible in the new Soot version.
        endDetails.setUsageMethodSignature(sinkInfo.getStmt().getInvokeExpr().getMethod().getSubSignature());
        endDetails.setUsageClassName(sinkInfo.getStmt().getInvokeExpr().getMethod().getDeclaringClass().getName());
        endDetails.setType(LocationType.Sink);

        return new SameTypedPair<LocationDetails>(startDetails, endDetails);
    }

    private SameTypedPair<LocationDetails> stitchSourceAndSink(
            SameTypedPair<LocationDetails> sourcePair, SameTypedPair<LocationDetails> sinkPair) {
        return new SameTypedPair<>(sourcePair.getFirst(), sinkPair.getSecond());
    }
}
