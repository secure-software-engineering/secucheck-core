package secucheck.analysis.SingleFlowAnalysis;

import secucheck.analysis.result.TaintFlowResult;

/**
 * This represents the Analysis for a single TaintFlow
 */
public interface SingleFlowAnalysis {
    TaintFlowResult run() throws Exception;
}
