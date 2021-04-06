package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.BackwardQuery;
import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.QueryGraph;
import boomerang.guided.DemandDrivenGuidedAnalysis;
import boomerang.scene.jimple.JimpleStatement;
import de.fraunhofer.iem.secucheck.analysis.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.Utility;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.LocationDetails;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.LocationType;
import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.SameTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import soot.SootMethod;
import soot.jimple.IdentityStmt;
import soot.jimple.ParameterRef;
import wpds.impl.Weight;

import java.util.*;

public class SecucheckBoomerangDemandDrivenAnalysis {
    private final SecucheckAnalysisConfiguration secucheckAnalysisConfiguration;

    public SecucheckBoomerangDemandDrivenAnalysis(SecucheckAnalysisConfiguration secucheckAnalysisConfiguration) {
        this.secucheckAnalysisConfiguration = secucheckAnalysisConfiguration;
    }

    public List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> run(Set<ForwardQuery> sources, Set<BackwardQuery> sinks, TaintFlowQueryImpl singleFlow) {

        List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> reachMap =
                new ArrayList<>();

        for (ForwardQuery source : sources) {
            HashMap<BackwardQuery, Boolean> foundSinks = new HashMap<>();
            sinks.stream().forEach(sink -> foundSinks.put(sink, false));

            BoomerangGPHandler boomerangGPHandler = new BoomerangGPHandler(singleFlow, this.secucheckAnalysisConfiguration);
            MyDefaultBoomerangOptions myDefaultBoomerangOptions = new MyDefaultBoomerangOptions(singleFlow);
            CustomDataFlowScope customDataFlowScope = new CustomDataFlowScope(singleFlow, this.secucheckAnalysisConfiguration);

            DemandDrivenGuidedAnalysis demandDrivenGuidedAnalysis = new DemandDrivenGuidedAnalysis(
                    boomerangGPHandler,
                    myDefaultBoomerangOptions,
                    customDataFlowScope);

            QueryGraph<Weight.NoWeight> queryGraph = demandDrivenGuidedAnalysis.run(source);

            for (Query sink : boomerangGPHandler.getFoundSinks()) {
                reachMap.add(new DifferentTypedPair<>(
                        singleFlow, getLocationDetailsPair(singleFlow, source, sink)));
            }

            Set<Query> queries = queryGraph.getNodes();
/*
            System.out.println("Critical = " + queries.size() + " : " + sinks.size());
            for (Query query : queries) {
                System.out.println(query);
            }*/
        }

        return reachMap;

    }

    private SameTypedPair<LocationDetails> getLocationDetailsPair(TaintFlowQueryImpl flowQuery,
                                                                  Query start, Query end) {

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
