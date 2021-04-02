package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis;

import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.CompositeTaintFlowQueryResult;

public interface CompositeTaintFlowAnalysis {

    CompositeTaintFlowQueryResult run() throws Exception;

}
