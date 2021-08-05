package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver;

import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.scene.AnalysisScope;
import boomerang.scene.jimple.BoomerangPretransformer;
import boomerang.scene.jimple.SootCallGraph;
import com.google.common.collect.Sets;
import de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis.SingleFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.configuration.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.guided.SecucheckBoomerangDemandDrivenAnalysis;
import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlow;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;
import de.fraunhofer.iem.secucheck.analysis.result.SingleTaintFlowAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowResult;
import soot.PackManager;
import soot.SceneTransformer;
import soot.Transform;

import java.util.*;

/**
 * Boomerang Solver, that solves the single TaintFlow spec
 */
public class BoomerangSingleFlowAnalysis implements SingleFlowAnalysis {

    /**
     * Current single TaintFlow specification
     */
    private final TaintFlowImpl singleFlow;

    /**
     * SecucheckAnalysisConfiguration given by the client
     */
    private final SecucheckAnalysisConfiguration configuration;

    /**
     * TaintFlowResult for the single TaintFlow specification
     */
    private final TaintFlowResult result;
    
    /**
     * List<EntryPoint> for holding all entry points for given single taint flow
     */
    private final List<EntryPoint> entryPoints;
    
    /**
     * Boolean value of whether only DSL-specified entry points should be used
     */
    private final boolean DSLEntryPoints;

    public BoomerangSingleFlowAnalysis(TaintFlowImpl singleFlow, SecucheckAnalysisConfiguration configuration, List<EntryPoint> entryPoints, boolean DSLEntryPoints) {
        this.singleFlow = singleFlow;
        this.configuration = configuration;
        this.result = new TaintFlowResult();
        this.entryPoints = entryPoints;
        this.DSLEntryPoints = DSLEntryPoints;
    }

    /**
     * Initializes the soot and run the analysis
     *
     * @return TaintFlowResult for the current single TaintFlow specification
     * @throws Exception Any exception
     */
    @Override
    public TaintFlowResult run() throws Exception {
        String classPath = Utility.getCombinedSootClassPath(this.configuration.getOs(),
                this.configuration.getApplicationClassPath(), this.configuration.getSootClassPathJars());
        
        if(this.entryPoints == null) {
            Utility.initializeSootWithEntryPoints(classPath, this.configuration.getAnalysisEntryPoints());
        }
        else {
        	if(this.DSLEntryPoints) {
        		Utility.initializeSootWithEntryPoints(classPath, this.entryPoints);
        	}
        	else {
        		List<EntryPoint> entryPoints = this.configuration.getAnalysisEntryPoints();
        		entryPoints.addAll(this.entryPoints);
        		List<EntryPoint> entryPointsWithoutDuplicates = new ArrayList<>(new HashSet<>(entryPoints));
        		Utility.initializeSootWithEntryPoints(classPath, entryPointsWithoutDuplicates);
        	}
        }
        
        Utility.loadAllParticipantMethods(singleFlow);

        Transform transform = new Transform("wjtp.ifds", createAnalysisTransformer());
        PackManager.v().getPack("wjtp").add(transform);
        PackManager.v().getPack("cg").apply();

        BoomerangPretransformer.v().apply();
        PackManager.v().getPack("wjtp").apply();
        BoomerangPretransformer.v().reset();
        return this.result;
    }

    /**
     * Creates the analysis transformer
     *
     * @return SceneTransformer
     */
    private SceneTransformer createAnalysisTransformer() {
        return new SceneTransformer() {
            protected void internalTransform(String phaseName, @SuppressWarnings("rawtypes") Map options) {
                executeAnalysis();
            }
        };
    }

    /**
     * Starts the analysis
     */
    private void executeAnalysis() {
        result.addQueryResultPairs(analyzePlainFlow(singleFlow));
    }

    /**
     * First it finds the seeds using the AnalysisScope, Then it runs the SecuchcekDemandDrivenAnalysis for finding the TaintFlows based on
     * the Boomeranf DemandDrivenAnalysis
     *
     * @param singleFlow Current single TaintFlow specification
     * @return List of Tainflow locations details for the current single TaintFlow specification
     */
    public List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>>
    analyzePlainFlow(TaintFlowImpl singleFlow) {

        List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>>
                reachMap = new ArrayList<>();

        // First get the seeds --- source ForwardQuery
        SootCallGraph callGraph = new SootCallGraph();
        AnalysisScope analysisScope = getAnalysisScope(singleFlow, callGraph);

        Set<ForwardQuery> source = computeSeeds(analysisScope);

        result.setSeedCount(source.size());

        if (source.size() != 0) {   // If seeds found then run the SecucheckBoomerangDemandDrivenAnalysis
            reachMap.addAll(new SecucheckBoomerangDemandDrivenAnalysis(this.configuration).run(source, singleFlow));
        }

        return reachMap;
    }

    /**
     * Returns the Analysiscope for finding the seeds
     *
     * @param taintFlow Current single TaintFlow specification
     * @param callGraph Soot callgraph
     * @return AnalysisScope
     */
    private AnalysisScope getAnalysisScope(TaintFlow taintFlow, SootCallGraph callGraph) {
        return new SingleFlowAnalysisScope(taintFlow, callGraph);
    }

    /**
     * Start finding the seeds from the AnalysisScope
     *
     * @param analysisScope AnalysisScope
     * @return Seeds-- ForwardQuery for each source method found in AnalysisScope
     */
    private Set<ForwardQuery> computeSeeds(AnalysisScope analysisScope) {

        Set<ForwardQuery> sources = Sets.newHashSet();
        Collection<Query> computeSeeds = analysisScope.computeSeeds();

        for (Query q : computeSeeds) {
            if (q instanceof ForwardQuery) {
                sources.add((ForwardQuery) q);
            }
        }
        return sources;
    }
}
