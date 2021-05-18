package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.FlowDroidSolver;

import de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis.SingleFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.configuration.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.SameTypedPair;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.Utility;
import de.fraunhofer.iem.secucheck.analysis.query.*;
import de.fraunhofer.iem.secucheck.analysis.result.LocationDetails;
import de.fraunhofer.iem.secucheck.analysis.result.LocationType;
import de.fraunhofer.iem.secucheck.analysis.result.SingleTaintFlowAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowResult;
import soot.*;
import soot.jimple.JimpleBody;
import soot.jimple.Stmt;
import soot.jimple.infoflow.Infoflow;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.config.IInfoflowConfig;
import soot.jimple.infoflow.entryPointCreators.DefaultEntryPointCreator;
import soot.jimple.infoflow.results.DataFlowResult;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.results.ResultSourceInfo;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;
import soot.jimple.internal.JNopStmt;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.options.Options;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/**
 * This is the FlowDroid solver
 */
public class FlowDroidSingleFlowAnalysis implements SingleFlowAnalysis {

    /**
     * Single TaintFlow
     */
    private final TaintFlowImpl singleFlow;

    /**
     * SecuCheck configuration
     */
    private final SecucheckAnalysisConfiguration configuration;

    /**
     * TaintFlow result
     */
    private final TaintFlowResult result;

    /**
     * Constructor
     *
     * @param singleFlow    Single TaintFlow
     * @param configuration SecuCheck configuration
     */
    public FlowDroidSingleFlowAnalysis(TaintFlowImpl singleFlow, SecucheckAnalysisConfiguration configuration) {
        this.singleFlow = singleFlow;
        this.configuration = configuration;
        this.result = new TaintFlowResult();
    }

    /**
     * This method reads the EasyTaintWrapper required for the FlowDroid from the resource folder.
     * <p>
     * Note: For now it is taken from the file manually. In Future, this file has to be generated during runtime from the
     * FluenTQL general propogators
     *
     * @return EasyTaintWrapper for the FlowDroid (For propogators)
     */
    private EasyTaintWrapper getTaintWrapper() {
        String fileName = "EasyTaintWrapperSource.txt";

        ClassLoader classLoader = getClass().getClassLoader();

        String content = "";
        try (InputStream inputStream = classLoader.getResourceAsStream(fileName)) {
            if (inputStream != null) {
                return new EasyTaintWrapper(inputStream);
            }
        } catch (IOException exception) {
            System.out.println(Arrays.toString(exception.getStackTrace()));
        }

        return null;
    }

    /**
     * Runs the Analysis
     *
     * @return TaintFlow result
     * @throws Exception If fails to initialize the Soot
     */
    @Override
    public TaintFlowResult run() throws Exception {

        String classPath = Utility.getCombinedSootClassPath(this.configuration.getOs(),
                this.configuration.getApplicationClassPath(), this.configuration.getSootClassPathJars());

        Utility.initializeSootWithEntryPoints(classPath, this.configuration.getAnalysisEntryPoints());
        Utility.loadAllParticipantMethods(singleFlow);

        List<String> entryMethods = getCanonicalEntryMethodSignatures(configuration.getAnalysisEntryPoints());
        DefaultEntryPointCreator entryPointCreator = new DefaultEntryPointCreator(entryMethods);
        Infoflow infoFlow = getInfoFlow();
        EasyTaintWrapper easyTaintWrapper = getTaintWrapper();

        if (easyTaintWrapper != null) {
            infoFlow.setTaintWrapper(easyTaintWrapper);
        }

        if (isPropogatorless(this.singleFlow)) {
            result.addQueryResultPairs(analyzePlainFlow(singleFlow, infoFlow, entryPointCreator, this.configuration));
        } else {
            result.addQueryResultPairs(analyzePropogatorFlow(singleFlow, infoFlow, entryPointCreator, this.configuration));
        }
        return this.result;
    }

    /**
     * Analyzes the single TaintFlow
     *
     * @param singleFlow        TaintFLow
     * @param infoFlow          InfoFlow
     * @param entryPointCreator Entry point for the Infoflow
     * @param configuration     SecuCheck configuration
     * @return Result
     */
    public List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>>
    analyzePlainFlow(TaintFlowImpl singleFlow, Infoflow infoFlow,
                     DefaultEntryPointCreator entryPointCreator, SecucheckAnalysisConfiguration configuration) {

        List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>>
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
                    SingleTaintFlowAnalysisResult res = new SingleTaintFlowAnalysisResult(
                            new DifferentTypedPair<>(singleFlow, locationPair),
                            null
                    );
                    reachMap.add(new DifferentTypedPair<>(singleFlow, res));
                }
            }
        }

        return reachMap;
    }

    /**
     * If there is a propogators mentioned in the specification, then this method is called. In this method
     * TaintFlow is divided into two taintflows from source to required propogator and second taintflow is from
     * required propogator to sink.
     *
     * @param singleFlow        TaintFLow
     * @param infoFlow          InfoFlow
     * @param entryPointCreator Entry point for the Infoflow
     * @param configuration     SecuCheck configuration
     * @return Result
     */
    public List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>>
    analyzePropogatorFlow(TaintFlowImpl singleFlow, Infoflow infoFlow,
                          DefaultEntryPointCreator entryPointCreator, SecucheckAnalysisConfiguration configuration) {

        //TODO: If there is a multiple through's is mentioned in the specification, then code might not handle that,
        // needs to check that in future.
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

        List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>>
                originalReachMap = new ArrayList<>(),
                reachMap1 = analyzePlainFlow(newQuery1, infoFlow, entryPointCreator, configuration),
                reachMap2 = analyzePlainFlow(newQuery2, infoFlow, entryPointCreator, configuration);

        if (reachMap1.size() != 0 && reachMap2.size() != 0) {
            for (DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>
                    sourcePair : reachMap1) {

                for (DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>
                        sinkPair : reachMap2) {

                    if (isSourceAndSinkMatching(sourcePair.getSecond().getLocationDetails().getSecond(),
                            sinkPair.getSecond().getLocationDetails().getSecond())) {
                        SameTypedPair<LocationDetails> stichedPair =
                                stitchSourceAndSink(sourcePair.getSecond().getLocationDetails().getSecond(),
                                        sinkPair.getSecond().getLocationDetails().getSecond());

                        originalReachMap.add(new
                                DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>
                                (singleFlow, new SingleTaintFlowAnalysisResult(new DifferentTypedPair<>(singleFlow, stichedPair), null)));
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

    /**
     * Returns the Infoflow for flowdroid
     *
     * @return Infoflow
     */
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
        infoFlow.getConfig().setInspectSources(false);
        infoFlow.getConfig().setLogSourcesAndSinks(true);
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

        // TODO: Not visible in the new Soot version.
        JimpleBasedInterproceduralCFG icfg = new JimpleBasedInterproceduralCFG();

        int sourceLineNumber = -1;
        int sourceColNumber = -1;
        for (Unit unit : Scene.v().getMethod(icfg.getMethodOf(sourceInfo.getStmt()).getSignature()).getActiveBody().getUnits()) {
            Stmt stmt = (Stmt) unit;

            if (sourceInfo.getStmt().equals(stmt)) {
                sourceLineNumber = stmt.getJavaSourceStartLineNumber();
                sourceColNumber = stmt.getJavaSourceStartColumnNumber();
            }
        }

        startDetails.setUsageStartLineNumber(sourceLineNumber);
        startDetails.setUsageEndLineNumber(-1);
        startDetails.setUsageStartColumnNumber(sourceColNumber);
        startDetails.setUsageEndColumnNumber(-1);

        startDetails.setUsageMethodSignature(icfg.getMethodOf(sourceInfo.getStmt()).getSignature());
        startDetails.setUsageClassName(icfg.getMethodOf(sourceInfo.getStmt()).getDeclaringClass().getName());
        startDetails.setType(LocationType.Source);

        ResultSinkInfo sinkInfo = dataFlowResult.getSink();

        int sinkLineNumber = -1;
        int sinkColNumber = -1;
        for (Unit unit : icfg.getMethodOf(sinkInfo.getStmt()).getActiveBody().getUnits()) {
            Stmt stmt = (Stmt) unit;

            if (sourceInfo.getStmt().equals(stmt)) {
                sinkLineNumber = stmt.getJavaSourceStartLineNumber();
                sinkColNumber = stmt.getJavaSourceStartColumnNumber();
            }
        }

        LocationDetails endDetails = new LocationDetails();
        // TODO: Not visible in the new Soot version.
        endDetails.setSourceClassName(sinkInfo.getStmt().getInvokeExpr().getMethodRef().getDeclaringClass().getName());
        endDetails.setMethodSignature(sinkInfo.getStmt().getInvokeExpr().getMethodRef().getSubSignature().getString());

        endDetails.setUsageStartLineNumber(sinkLineNumber);
        endDetails.setUsageEndLineNumber(-1);
        endDetails.setUsageStartColumnNumber(sinkColNumber);
        endDetails.setUsageEndColumnNumber(-1);

        // TODO: Not visible in the new Soot version.
        endDetails.setUsageMethodSignature(icfg.getMethodOf(sinkInfo.getStmt()).getSignature());
        endDetails.setUsageClassName(icfg.getMethodOf(sinkInfo.getStmt()).getDeclaringClass().getName());
        endDetails.setType(LocationType.Sink);

        return new SameTypedPair<LocationDetails>(startDetails, endDetails);
    }

    private SameTypedPair<LocationDetails> stitchSourceAndSink(
            SameTypedPair<LocationDetails> sourcePair, SameTypedPair<LocationDetails> sinkPair) {
        return new SameTypedPair<>(sourcePair.getFirst(), sinkPair.getSecond());
    }
}
