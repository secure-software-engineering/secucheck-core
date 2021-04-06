package de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis;

import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;

public interface SingleFlowAnalysis {
    TaintFlowQueryResult run() throws Exception;
}
