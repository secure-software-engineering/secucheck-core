package de.fraunhofer.iem.secucheck.analysis.result;

/**
 * Secucheck analysis result listener
 */
public interface AnalysisResultListener {
    /**
     * Returns true if user cancelled the running analysis
     *
     * @return Boolean
     */
    public boolean isCancelled();

    /**
     * Reports the complete Secucheck taint analysis result to the listener
     *
     * @param result Secucheck analysis result
     */
    public void reportCompleteResult(SecucheckTaintAnalysisResult result);

    /**
     * Reports just the  Secucheck taint flow query analysis result
     *
     * @param result SecucheckTaintFlowQueryResult
     */
    public void reportSecucheckTaintFlowQueryResult(SecucheckTaintFlowQueryResult result);

    public void reportTaintFlowResult(TaintFlowResult result);
}