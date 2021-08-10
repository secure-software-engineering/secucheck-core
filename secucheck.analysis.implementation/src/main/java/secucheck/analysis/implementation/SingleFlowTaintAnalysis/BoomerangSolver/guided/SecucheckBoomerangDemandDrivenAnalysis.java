package secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.BackwardQuery;
import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.QueryGraph;
import boomerang.guided.DemandDrivenGuidedAnalysis;
import boomerang.scene.jimple.JimpleStatement;
import secucheck.analysis.configuration.SecucheckAnalysisConfiguration;
import secucheck.analysis.datastructures.SameTypedPair;
import secucheck.analysis.datastructures.TaintFlowPath;
import secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.Utility;
import secucheck.analysis.datastructures.DifferentTypedPair;
import secucheck.analysis.implementation.SingleFlowTaintAnalysis.datastructure.BoomerangTaintFlowPath;
import secucheck.analysis.query.TaintFlowImpl;
import secucheck.analysis.result.LocationDetails;
import secucheck.analysis.result.LocationType;
import secucheck.analysis.result.SingleTaintFlowAnalysisResult;
import soot.SootMethod;
import soot.jimple.IdentityStmt;
import soot.jimple.ParameterRef;
import wpds.impl.Weight;

import java.util.*;

/**
 * This is the Secucheck DemandDrivenAnalysis based on the Boomerang DemandDrivenAnalysis
 */
public class SecucheckBoomerangDemandDrivenAnalysis {
    /**
     * SecucheckAnalysisConfiguration given by the client
     */
    private final SecucheckAnalysisConfiguration secucheckAnalysisConfiguration;

    public SecucheckBoomerangDemandDrivenAnalysis(SecucheckAnalysisConfiguration secucheckAnalysisConfiguration) {
        this.secucheckAnalysisConfiguration = secucheckAnalysisConfiguration;
    }

    public void printPath(BoomerangTaintFlowPath node) {
        if (node == null)
            return;

        if (node.getNodeValue() == null)
            System.out.println("--> null");
        else
            System.out.println("--> " + (Query) node.getNodeValue());

        for (TaintFlowPath child : node.getChildrenNodes())
            printPath((BoomerangTaintFlowPath) child);
    }

    /**
     * Runs the DemandDrivenAnalysis
     *
     * @param sources    Set of sources(ForwardQuery--- seeds)
     * @param singleFlow Current single TaintFlow specification---looking for this TaintFlow
     * @return Returns the result for the single given TaintFlow-specification ( There may be more than one TaintFlow in the result)
     */
    public List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>> run(Set<ForwardQuery> sources, TaintFlowImpl singleFlow) {

        List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>> reachMap = new ArrayList<>();

        for (ForwardQuery source : sources) {
            BoomerangTaintFlowPath boomerangTaintFlowPath = new BoomerangTaintFlowPath(
                    source, null, true, false);
            BoomerangGPHandler boomerangGPHandler = new BoomerangGPHandler(singleFlow, this.secucheckAnalysisConfiguration, boomerangTaintFlowPath);
            SecucheckDefaultBoomerangOptions secucheckDefaultBoomerangOptions = new SecucheckDefaultBoomerangOptions(singleFlow);
            CustomDataFlowScope customDataFlowScope = new CustomDataFlowScope(singleFlow, this.secucheckAnalysisConfiguration);

            DemandDrivenGuidedAnalysis demandDrivenGuidedAnalysis = new DemandDrivenGuidedAnalysis(
                    boomerangGPHandler,
                    secucheckDefaultBoomerangOptions,
                    customDataFlowScope);

            QueryGraph<Weight.NoWeight> queryGraph = demandDrivenGuidedAnalysis.run(source);

            for (DifferentTypedPair<BackwardQuery, BoomerangTaintFlowPath> sinkNode : boomerangGPHandler.getFoundSinks()) {
                BackwardQuery sink = sinkNode.getFirst();

                SingleTaintFlowAnalysisResult res = new SingleTaintFlowAnalysisResult(
                        new DifferentTypedPair<>(singleFlow, getLocationDetailsPair(source, sink)),
                        sinkNode.getSecond(),
                        secucheckAnalysisConfiguration.isPostProcessResult()
                );
                reachMap.add(new DifferentTypedPair<>(singleFlow, res));

                if (secucheckAnalysisConfiguration.isPostProcessResult()) {
                    System.out.println("***** TaintFlow *****");
                    printPath((BoomerangTaintFlowPath) res.getPath());
                    System.out.println("*********************");
                }
            }
        }

        return reachMap;

    }

    /**
     * Creates the Location detail for the found taintflow
     *
     * @param start Source
     * @param end   Sink
     * @return Location details
     */
    private SameTypedPair<LocationDetails> getLocationDetailsPair(Query start, Query end) {

        // source location detail
        LocationDetails startDetails = new LocationDetails();

        startDetails.setSourceClassName(start.cfgEdge().getMethod().getDeclaringClass().getName());
        startDetails.setMethodSignature(start.cfgEdge().getMethod().getSubSignature());

        // When parameter is tainted.
        // Left and Right Op() methods don't work for IdentityStmt inside JimpleStatement.
        if (start.cfgEdge().getX().isIdentityStmt() && start.cfgEdge().getX() instanceof JimpleStatement) {
            JimpleStatement jimpleStament = (JimpleStatement) start.cfgEdge().getX();
            IdentityStmt identityStmt = (IdentityStmt) jimpleStament.getDelegate();

            if (identityStmt.getRightOp() instanceof ParameterRef) {
                SootMethod sootMethod = Utility.getSootMethod(start.cfgEdge().getX().getMethod());
                startDetails.setUsageStartLineNumber(sootMethod.getJavaSourceStartLineNumber());
                startDetails.setUsageEndLineNumber(-1);
                startDetails.setUsageStartColumnNumber(sootMethod.getJavaSourceStartColumnNumber());
                startDetails.setUsageEndColumnNumber(-1);
            }
        } else {
            startDetails.setUsageStartLineNumber(start.cfgEdge().getX().getStartLineNumber());
            startDetails.setUsageEndLineNumber(start.cfgEdge().getX().getEndLineNumber());
            startDetails.setUsageStartColumnNumber(start.cfgEdge().getX().getStartColumnNumber());
            startDetails.setUsageEndColumnNumber(start.cfgEdge().getX().getEndColumnNumber());
        }

        startDetails.setUsageMethodSignature(start.cfgEdge().getX().getMethod().getSubSignature());
        startDetails.setUsageClassName(start.cfgEdge().getX().getMethod().getDeclaringClass().getName());
        startDetails.setType(LocationType.Source);

        // Sink location detail
        LocationDetails endDetails = new LocationDetails();

        endDetails.setSourceClassName(end.cfgEdge().getMethod().getDeclaringClass().getName());
        endDetails.setMethodSignature(end.cfgEdge().getMethod().getSubSignature());

        endDetails.setUsageStartLineNumber(end.cfgEdge().getX().getStartLineNumber());
        endDetails.setUsageEndLineNumber(end.cfgEdge().getX().getEndLineNumber());
        endDetails.setUsageStartColumnNumber(end.cfgEdge().getX().getStartColumnNumber());
        endDetails.setUsageEndColumnNumber(end.cfgEdge().getX().getEndColumnNumber());

        endDetails.setUsageMethodSignature(end.cfgEdge().getX().getMethod().getSubSignature());
        endDetails.setUsageClassName(end.cfgEdge().getX().getMethod().getDeclaringClass().getName());
        endDetails.setType(LocationType.Sink);

        return new SameTypedPair<LocationDetails>(startDetails, endDetails);
    }
}
