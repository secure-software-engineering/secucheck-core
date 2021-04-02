package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.QueryGraph;
import boomerang.guided.DemandDrivenGuidedAnalysis;
import wpds.impl.Weight;

import java.util.Set;

public class SecucheckBoomerangDemandDrivenAnalysis {
    public static void run(Set<ForwardQuery> sources) {
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
    }
}
