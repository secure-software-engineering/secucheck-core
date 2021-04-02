package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis;

import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.TaintFlowQueryResult;

public interface SingleFlowAnalysis {
    TaintFlowQueryResult run() throws Exception;
}
