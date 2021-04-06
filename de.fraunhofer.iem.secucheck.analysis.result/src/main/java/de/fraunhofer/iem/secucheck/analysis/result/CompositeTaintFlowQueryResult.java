package de.fraunhofer.iem.secucheck.analysis.result;

import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;

public final class CompositeTaintFlowQueryResult implements AnalysisResult {

    private final List<DifferentTypedPair<TaintFlowImpl, TaintFlowQueryResult>> results;

    public CompositeTaintFlowQueryResult() {
        this.results = new ArrayList<DifferentTypedPair<TaintFlowImpl, TaintFlowQueryResult>>();
    }

    public void addResult(TaintFlowImpl flowQuery, TaintFlowQueryResult result) {
        this.results.add(
                new DifferentTypedPair<TaintFlowImpl, TaintFlowQueryResult>(flowQuery, result));
    }

    public List<DifferentTypedPair<TaintFlowImpl, TaintFlowQueryResult>> getResults() {
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
