package secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.flowfunction.IForwardFlowFunction;
import boomerang.scene.jimple.IntAndStringBoomerangOptions;
import secucheck.analysis.query.TaintFlowImpl;

/**
 * Default Boomerang options for the DemandDriven analysis
 * <p>
 * Note:
 * 1. Currently maxFieldDepth, maxUnbalancedCallDepth, and maxCallDepth is hard coded to 5.
 * 2. Since our implementation uses only BackwardQuery, therefore we are using custom ForwardFlow functions only.
 */
public class SecucheckDefaultBoomerangOptions extends IntAndStringBoomerangOptions {
    /**
     * Current single TaintFlow specification
     */
    private final TaintFlowImpl singleFlow;

    public SecucheckDefaultBoomerangOptions(TaintFlowImpl singleFlow) {
        this.singleFlow = singleFlow;
    }

    @Override
    public StaticFieldStrategy getStaticFieldStrategy() {
        return StaticFieldStrategy.FLOW_SENSITIVE;
    }

    @Override
    public boolean onTheFlyCallGraph() {
        return false;
    }

    @Override
    public boolean trackStaticFieldAtEntryPointToClinit() {
        return true;
    }

    @Override
    public int maxCallDepth() {
        return 5;
    }

    @Override
    public int maxUnbalancedCallDepth() {
        return 5;
    }

    @Override
    public int maxFieldDepth() {
        return 5;
    }

    @Override
    public boolean allowMultipleQueries() {
        return true;
    }

    @Override
    public IForwardFlowFunction getForwardFlowFunctions() {
        return new SecucheckDefaultForwardFlowFunction(this, singleFlow);
    }
}
