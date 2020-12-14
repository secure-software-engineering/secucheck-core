package de.fraunhofer.iem.secucheck.analysis.internal;

import de.fraunhofer.iem.secucheck.analysis.result.CompositeTaintFlowQueryResult;

public interface CompositeTaintFlowAnalysis {
	
	CompositeTaintFlowQueryResult run() throws Exception;
	
}
