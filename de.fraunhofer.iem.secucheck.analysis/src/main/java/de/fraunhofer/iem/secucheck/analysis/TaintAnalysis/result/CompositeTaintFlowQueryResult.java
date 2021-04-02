package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result;

import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;

public final class CompositeTaintFlowQueryResult implements AnalysisResult {

    private final List<DifferentTypedPair<TaintFlowQueryImpl, TaintFlowQueryResult>> results;

    public CompositeTaintFlowQueryResult() {
        this.results = new ArrayList<DifferentTypedPair<TaintFlowQueryImpl, TaintFlowQueryResult>>();
    }

    public void addResult(TaintFlowQueryImpl flowQuery, TaintFlowQueryResult result) {
        this.results.add(
                new DifferentTypedPair<TaintFlowQueryImpl, TaintFlowQueryResult>(flowQuery, result));
    }

    public List<DifferentTypedPair<TaintFlowQueryImpl, TaintFlowQueryResult>> getResults() {
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
