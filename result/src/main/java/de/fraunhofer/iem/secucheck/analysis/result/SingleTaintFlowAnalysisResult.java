package de.fraunhofer.iem.secucheck.analysis.result;

import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.SameTypedPair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.TaintFlowPath;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;

/**
 * This is the result for the SingleFlowAnalysis.
 *
 * @author Ranjith Krishnamurthy
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
