package de.fraunhofer.iem.secucheck.analysis;

import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintFlowQueryResult;

/**
 * This is the interface for analysing the given TaintFlowQuery in the configuration and returns the SecucheckTaintFlowQueryResult
 */
public interface SecucheckTaintFlowQueryAnalysis {
    SecucheckTaintFlowQueryResult run() throws Exception;
}
