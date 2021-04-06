package de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis;

import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowResult;

/**
 * This represents the Analysis for a single TaintFlow
 */
public interface SingleFlowAnalysis {
    TaintFlowResult run() throws Exception;
}
