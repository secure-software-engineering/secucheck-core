package de.fraunhofer.iem.secucheck.analysis.result;

import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.SecucheckTaintFlowQueryImpl;

import java.util.ArrayList;
import java.util.List;

public final class SecucheckTaintAnalysisResult implements AnalysisResult {

    private List<DifferentTypedPair<SecucheckTaintFlowQueryImpl, CompositeTaintFlowQueryResult>> results;

    public SecucheckTaintAnalysisResult() {
        this.results = new ArrayList<DifferentTypedPair<SecucheckTaintFlowQueryImpl, CompositeTaintFlowQueryResult>>();
    }

    public void addResult(SecucheckTaintFlowQueryImpl compositeQuery, CompositeTaintFlowQueryResult result) {
        this.results.add(
                new DifferentTypedPair<SecucheckTaintFlowQueryImpl, CompositeTaintFlowQueryResult>
                        (compositeQuery, result));
    }

    public List<DifferentTypedPair<SecucheckTaintFlowQueryImpl, CompositeTaintFlowQueryResult>> getResults() {
        return this.results;
    }

    @Override
    public int size() {
        return this.results.size();
    }

    @Override
    public void clear() {
        results.clear();
    }
}
