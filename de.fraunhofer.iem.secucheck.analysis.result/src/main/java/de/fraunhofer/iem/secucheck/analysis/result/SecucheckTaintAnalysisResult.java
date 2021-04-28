package de.fraunhofer.iem.secucheck.analysis.result;

import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.SecucheckTaintFlowQueryImpl;

import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of the AnalysisResult. This contains the complete result of TaintAnalysis i.e. for all TaintFlowQuery
 */
public final class SecucheckTaintAnalysisResult implements AnalysisResult {

    private List<DifferentTypedPair<SecucheckTaintFlowQueryImpl, SecucheckTaintFlowQueryResult>> results;
    private String startTime;
    private String endTime;
    private long elapsedTime;

    @Override
    public String getStartTime() {
        return this.startTime;
    }

    @Override
    public String getEndTime() {
        return this.endTime;
    }

    @Override
    public long getExecutionTime() {
        return this.elapsedTime;
    }

    public void setStartTime(String startTime) {
        this.startTime = startTime;
    }

    public void setEndTime(String endTime) {
        this.endTime = endTime;
    }

    public void setExecutionTime(long elapsedTime) {
        this.elapsedTime = elapsedTime;
    }

    public SecucheckTaintAnalysisResult() {
        this.results = new ArrayList<DifferentTypedPair<SecucheckTaintFlowQueryImpl, SecucheckTaintFlowQueryResult>>();
    }

    /**
     * Adds the single SecucheckTaintFlowQueryResult result to the list
     *
     * @param secucheckTaintFlowQuery Secucheck taint flow query
     * @param result                  SecucheckTaintFlowQueryResult
     */
    public void addResult(SecucheckTaintFlowQueryImpl secucheckTaintFlowQuery, SecucheckTaintFlowQueryResult result) {
        this.results.add(
                new DifferentTypedPair<SecucheckTaintFlowQueryImpl, SecucheckTaintFlowQueryResult>
                        (secucheckTaintFlowQuery, result));
    }

    public List<DifferentTypedPair<SecucheckTaintFlowQueryImpl, SecucheckTaintFlowQueryResult>> getResults() {
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
