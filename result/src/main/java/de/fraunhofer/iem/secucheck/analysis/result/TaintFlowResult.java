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

    private final List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>> resultMap;
    private int seedCount = 0;

    public void setSeedCount(int seedCount) {
        this.seedCount = seedCount;
    }

    public int getSeedCount() {
        return seedCount;
    }

    public TaintFlowResult() {
        this.resultMap =
                new ArrayList<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>>();
    }

    /**
     * Adds the single result of the TaintFlow
     *
     * @param taintFlow TaintFlow
     * @param result    LocationDetail of this TaintFlow found
     */
    public void addQueryResultPair(TaintFlowImpl taintFlow,
                                   SingleTaintFlowAnalysisResult result) {
        this.resultMap.add(
                new DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>(taintFlow, result));
    }

    public void addQueryResultPairs(
            List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>> pairs) {
        this.resultMap.addAll(pairs);
    }

    public void clear() {
        this.resultMap.clear();
    }

    @Override
    public int size() {
        return this.resultMap.size();
    }

    public List<DifferentTypedPair<TaintFlowImpl, SingleTaintFlowAnalysisResult>>
    getQueryResultMap() {
        return this.resultMap;
    }
}