package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver;

import boomerang.BackwardQuery;
import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.scene.AnalysisScope;
import boomerang.scene.jimple.BoomerangPretransformer;
import boomerang.scene.jimple.SootCallGraph;
import com.google.common.collect.Sets;
import de.fraunhofer.iem.secucheck.analysis.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.guided.SecucheckBoomerangDemandDrivenAnalysis;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.SingleFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.LocationDetails;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.TaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.SameTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import soot.PackManager;
import soot.SceneTransformer;
import soot.Transform;

import java.util.*;

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
        result.addQueryResultPairs(analyzePlainFlow(singleFlow));
    }

    public List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>>
    analyzePlainFlow(TaintFlowQueryImpl singleFlow) {

        List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>>
                reachMap = new ArrayList<>();

        SootCallGraph callGraph = new SootCallGraph();
        AnalysisScope analysisScope = getAnalysisScope(singleFlow, callGraph);
        Seeds seeds = computeSeeds(analysisScope);

        if (seeds.getSources().size() != 0 && seeds.getSinks().size() != 0) {
            reachMap.addAll(new SecucheckBoomerangDemandDrivenAnalysis(this.configuration).run(seeds.getSources(), seeds.getSinks(), singleFlow));
        }

        return reachMap;
    }

    private AnalysisScope getAnalysisScope(TaintFlowQuery taintFlow, SootCallGraph callGraph) {
        return new SingleFlowAnalysisScope(taintFlow, callGraph);
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
/*
        System.out.println("\n\n\nSources: " + sources.size());
        for (ForwardQuery forwardQuery : sources) {
            System.out.println(forwardQuery.var());
        }

		System.out.println("\n\n\nSinks:");
		for (BackwardQuery backwardQuery : sinks) {
			System.out.println(backwardQuery.var().m().toString());
		}
*/
        return new Seeds(sources, sinks);
    }
}