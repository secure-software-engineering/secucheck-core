package secucheck.analysis;

import java.util.List;

import secucheck.analysis.configuration.SecucheckAnalysisConfiguration;
import secucheck.analysis.query.SecucheckTaintFlowQueryImpl;
import secucheck.analysis.result.SecucheckTaintAnalysisResult;

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
     * Runs the TaintAnalysis for the given list of TaintFlowQueries
     *
     * @param flowQueries TaintFlowQueries
     * @return TaintAnalysis results
     * @throws Exception Any kind of exceptions.
     */
    SecucheckTaintAnalysisResult run(List<SecucheckTaintFlowQueryImpl> flowQueries) throws Exception;
}
