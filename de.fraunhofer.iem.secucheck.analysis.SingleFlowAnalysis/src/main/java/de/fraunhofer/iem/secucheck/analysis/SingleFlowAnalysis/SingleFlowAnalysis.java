package de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis;

import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowResult;

public interface SingleFlowAnalysis {
    TaintFlowResult run() throws Exception;
}
