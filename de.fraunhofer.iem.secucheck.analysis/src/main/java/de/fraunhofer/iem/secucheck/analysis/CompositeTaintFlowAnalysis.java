package de.fraunhofer.iem.secucheck.analysis;

import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintFlowQueryResult;

public interface CompositeTaintFlowAnalysis {

    SecucheckTaintFlowQueryResult run() throws Exception;

}
