package secucheck.analysis.result;

import secucheck.analysis.datastructures.DifferentTypedPair;
import secucheck.analysis.datastructures.SameTypedPair;
import secucheck.analysis.datastructures.TaintFlowPath;
import secucheck.analysis.query.TaintFlowImpl;

/**
 * This is the result for the SingleFlowAnalysis.
 *
 */
public class SingleTaintFlowAnalysisResult {
    private final DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>> resultMap;
    private final boolean isTaintFlowPathIncluded;
    private final TaintFlowPath path;

    public SingleTaintFlowAnalysisResult(
            DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>> resultMap,
            TaintFlowPath path,
            boolean isTaintFlowPathIncluded) {
        this.resultMap = resultMap;
        this.path = path;
        this.isTaintFlowPathIncluded = isTaintFlowPathIncluded;
    }


    public DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>> getLocationDetails() {
        return this.resultMap;
    }

    public TaintFlowPath getPath() {
        return path;
    }

    public boolean isTaintFlowPathIncluded() {
        return  isTaintFlowPathIncluded;
    }
}
