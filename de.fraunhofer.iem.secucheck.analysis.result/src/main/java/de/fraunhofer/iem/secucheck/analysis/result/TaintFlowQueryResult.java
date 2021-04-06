package de.fraunhofer.iem.secucheck.analysis.result;

import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.datastructures.SameTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;

import java.util.ArrayList;
import java.util.List;

public class TaintFlowQueryResult implements AnalysisResult {

    private final List<DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>> resultMap;

    public TaintFlowQueryResult() {
        this.resultMap =
                new ArrayList<DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>>();
    }

    public void addQueryResultPair(TaintFlowImpl query,
                                   SameTypedPair<LocationDetails> result) {
        this.resultMap.add(
                new DifferentTypedPair<TaintFlowImpl, SameTypedPair<LocationDetails>>(query, result));
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