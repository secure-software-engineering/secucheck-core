package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver;

import boomerang.BackwardQuery;
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
import de.fraunhofer.iem.secucheck.analysis.query.Variable;
import de.fraunhofer.iem.secucheck.analysis.result.SingleTaintFlowAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowResult;
import soot.PackManager;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootMethod;
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
        
        List<SootMethod> entryPointsinCallGraph = Scene.v().getEntryPoints();
        System.out.println("The constructed call graph has "+entryPointsinCallGraph.size()+" entry points.");

        int numEdgesInCallGraph = Scene.v().getCallGraph().size();
        System.out.println("The constructed call graph has "+numEdgesInCallGraph+" edges.");
        
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
     * the Boomerang DemandDrivenAnalysis
     *
     * @param singleFlow Current single TaintFlow specification
     * @return List of Taintflow locations details for the current single TaintFlow specification
     */
    public List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>>
    analyzePlainFlow(TaintFlowImpl singleFlow) {

        List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>>
                reachMap = new ArrayList<>();

        SootCallGraph callGraph = new SootCallGraph();
        
        if(singleFlow.getFrom().size() == 1 && singleFlow.getFrom().get(0) instanceof Variable) {
        	// First get the seeds --- sink BackwardQuery
        	AnalysisScope analysisScope = getBackwardAnalysisScope(singleFlow, callGraph);
        	Set<BackwardQuery> sink = computeSeedsForBackwardFlow(analysisScope);
        	result.setSeedCount(sink.size());
            if (sink.size() != 0) {   // If seeds found then run the SecucheckBoomerangDemandDrivenAnalysis
                reachMap.addAll(new SecucheckBoomerangDemandDrivenAnalysis(this.configuration).runForBackwardFlow(sink, singleFlow));
            }
        }
        else if(singleFlow.getFrom().size() <= singleFlow.getTo().size()) {
        	// First get the seeds --- source ForwardQuery
        	AnalysisScope analysisScope = getForwardAnalysisScope(singleFlow, callGraph);
            Set<ForwardQuery> source = computeSeedsForForwardFlow(analysisScope);
            result.setSeedCount(source.size());
            if (source.size() != 0) {   // If seeds found then run the SecucheckBoomerangDemandDrivenAnalysis
                reachMap.addAll(new SecucheckBoomerangDemandDrivenAnalysis(this.configuration).runForForwardFlow(source, singleFlow));
            }
        }
        else {
        	// First get the seeds --- sink BackwardQuery
        	AnalysisScope analysisScope = getBackwardAnalysisScope(singleFlow, callGraph);
        	Set<BackwardQuery> sink = computeSeedsForBackwardFlow(analysisScope);
        	result.setSeedCount(sink.size());
            if (sink.size() != 0) {   // If seeds found then run the SecucheckBoomerangDemandDrivenAnalysis
                reachMap.addAll(new SecucheckBoomerangDemandDrivenAnalysis(this.configuration).runForBackwardFlow(sink, singleFlow));
            }
        }

        return reachMap;
    }

    /**
     * Returns the analysis scope for finding the seeds in forward flow
     *
     * @param taintFlow Current single TaintFlow specification
     * @param callGraph Soot call graph
     * @return AnalysisScope
     */
    private AnalysisScope getForwardAnalysisScope(TaintFlow taintFlow, SootCallGraph callGraph) {
        return new SingleForwardFlowAnalysisScope(taintFlow, callGraph);
    }
    
    /**
     * Returns the analysis scope for finding the seeds in backward flow
     *
     * @param taintFlow Current single TaintFlow specification
     * @param callGraph Soot call graph
     * @return AnalysisScope
     */
    private AnalysisScope getBackwardAnalysisScope(TaintFlow taintFlow, SootCallGraph callGraph) {
        return new SingleBackwardFlowAnalysisScope(taintFlow, callGraph);
    }

    /**
     * Start finding the seeds from the AnalysisScope
     *
     * @param analysisScope AnalysisScope
     * @return Seeds-- ForwardQuery for each source method found in AnalysisScope
     */
    private Set<ForwardQuery> computeSeedsForForwardFlow(AnalysisScope analysisScope) {

        Set<ForwardQuery> sources = Sets.newHashSet();
        Collection<Query> computeSeeds = analysisScope.computeSeeds();

        for (Query q : computeSeeds) {
            if (q instanceof ForwardQuery) {
                sources.add((ForwardQuery) q);
            }
        }
        return sources;
    }
    
    /**
     * Start finding the seeds from the AnalysisScope
     *
     * @param analysisScope AnalysisScope
     * @return Seeds-- BackwardQuery for each sink method found in AnalysisScope
     */
    private Set<BackwardQuery> computeSeedsForBackwardFlow(AnalysisScope analysisScope) {

        Set<BackwardQuery> sinks = Sets.newHashSet();
        Collection<Query> computeSeeds = analysisScope.computeSeeds();

        for (Query q : computeSeeds) {
            if (q instanceof BackwardQuery) {
                sinks.add((BackwardQuery) q);
            }
        }
        return sinks;
    }
    
}
