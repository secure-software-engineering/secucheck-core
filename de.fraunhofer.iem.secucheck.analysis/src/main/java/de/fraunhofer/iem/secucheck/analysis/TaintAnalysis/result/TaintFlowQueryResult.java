package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result;

import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.SameTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;

import java.util.ArrayList;
import java.util.List;

public class TaintFlowQueryResult implements AnalysisResult {

    private final List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> resultMap;

    public TaintFlowQueryResult() {
        this.resultMap =
                new ArrayList<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>>();
    }

    public void addQueryResultPair(TaintFlowQueryImpl query,
                                   SameTypedPair<LocationDetails> result) {
        this.resultMap.add(
                new DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>(query, result));
    }

    public void addQueryResultPairs(
            List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>> pairs) {
        this.resultMap.addAll(pairs);
    }

    public void clear() {
        this.resultMap.clear();
    }

    @Override
    public int size() {
        return this.resultMap.size();
    }

    public List<DifferentTypedPair<TaintFlowQueryImpl, SameTypedPair<LocationDetails>>>
    getQueryResultMap() {
        return this.resultMap;
    }
}