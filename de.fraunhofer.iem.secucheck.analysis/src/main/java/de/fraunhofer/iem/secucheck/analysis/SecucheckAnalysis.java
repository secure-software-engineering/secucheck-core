package de.fraunhofer.iem.secucheck.analysis;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.SecucheckTaintAnalysisResult;

/**
 * Top level for the Secucheck analysis
 */
public interface SecucheckAnalysis {

    /**
     * Sets the configurations for the Secucheck analysis.
     *
     * @param configuration Configuration settings for analysis.
     */
    void setConfiguration(SecucheckAnalysisConfiguration configuration);

    /**
     * Getter for the configuration
     *
     * @return Secucheck configuration
     */
    SecucheckAnalysisConfiguration getConfiguration();

    /**
     * Runs the TaintAnalysis
     *
     * @param flowQueries TaintFlowQueries
     * @return TaintAnalysis results
     * @throws Exception Any kind of exceptions.
     */
    SecucheckTaintAnalysisResult run(List<CompositeTaintFlowQueryImpl> flowQueries) throws Exception;
}
