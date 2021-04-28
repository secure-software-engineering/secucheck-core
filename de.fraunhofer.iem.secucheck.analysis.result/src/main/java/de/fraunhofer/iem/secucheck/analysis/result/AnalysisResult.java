package de.fraunhofer.iem.secucheck.analysis.result;

/**
 * Secucheck analysis result
 */
public interface AnalysisResult {
    /**
     * Size of the result
     *
     * @return Size of the result
     */
    public int size();

    /**
     * Clear the complete result
     */
    public void clear();

    /**
     * Start time of the analysis
     *
     * @return Start time of the analysis
     */
    public String getStartTime();

    /**
     * End time of the analysis
     *
     * @return End time of the analysis
     */
    public String getEndTime();

    /**
     * Total execution time of the analsis
     *
     * @return Elapsed time of analysis
     */
    public long getExecutionTime();
}
