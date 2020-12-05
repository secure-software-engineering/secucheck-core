package de.fraunhofer.iem.secucheck.analysis.internal;

import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;

public interface SingleFlowAnalysis {
	TaintFlowQueryResult run();
}
