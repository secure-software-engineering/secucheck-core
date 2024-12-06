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
}
