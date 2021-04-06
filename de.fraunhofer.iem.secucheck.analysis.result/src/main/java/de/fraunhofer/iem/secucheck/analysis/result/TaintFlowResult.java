package de.fraunhofer.iem.secucheck.analysis.result;

import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.SameTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;

import java.util.ArrayList;
import java.util.List;

/**
 * This contains the result of the single TaintFlow.
 */
public class TaintFlowResult implements AnalysisResult {

    private final List<DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>> resultMap;

    public TaintFlowResult() {
        this.resultMap =
                new ArrayList<DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>>();
    }

    /**
     * Adds the single result of the TaintFlow
     *
     * @param taintFlow TaintFlow
     * @param result    LocationDetail of this TaintFlow found
     */
    public void addQueryResultPair(TaintFlowImpl taintFlow,
                                   SameTypedPair<LocationDetails> result) {
        this.resultMap.add(
                new DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>(taintFlow, result));
    }

    public void addQueryResultPairs(
            List<DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>> pairs) {
        this.resultMap.addAll(pairs);
    }

    public void clear() {
        this.resultMap.clear();
    }

    @Override
    public int size() {
        return this.resultMap.size();
    }

    public List<DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>>
    getQueryResultMap() {
        return this.resultMap;
    }
}