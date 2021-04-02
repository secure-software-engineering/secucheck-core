package de.fraunhofer.iem.secucheck.analysis.internal;

import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.TaintFlowQueryResult;

public interface SingleFlowAnalysis {
	TaintFlowQueryResult run() throws Exception;
}
