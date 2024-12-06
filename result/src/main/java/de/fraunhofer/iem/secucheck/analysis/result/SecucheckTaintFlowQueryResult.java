package de.fraunhofer.iem.secucheck.analysis.result;

import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;

/**
 * This contains the result of the single TaintFlowQuery
 */
public final class SecucheckTaintFlowQueryResult implements AnalysisResult {

    private final List<DifferentTypedPair<TaintFlowImpl, TaintFlowResult>> results;
    private int totalSeedCount = 0;

    public int getTotalSeedCount() {
        return totalSeedCount;
    }

    public void setTotalSeedCount(int totalSeedCount) {
        this.totalSeedCount = totalSeedCount;
    }

    public SecucheckTaintFlowQueryResult() {
        this.results = new ArrayList<DifferentTypedPair<TaintFlowImpl, TaintFlowResult>>();
    }

    /**
     * Adds the single result of the TaintFlow
     *
     * @param taintFlow TaintFlow
     * @param result    TaintFlowResult
     */
    public void addResult(TaintFlowImpl taintFlow, TaintFlowResult result) {
        this.results.add(
                new DifferentTypedPair<TaintFlowImpl, TaintFlowResult>(taintFlow, result));
    }

    public List<DifferentTypedPair<TaintFlowImpl, TaintFlowResult>> getResults() {
        return this.results;
    }

    @Override
    public int size() {
        return this.results.size();
    }

    @Override
    public void clear() {
        this.results.clear();
    }
}
