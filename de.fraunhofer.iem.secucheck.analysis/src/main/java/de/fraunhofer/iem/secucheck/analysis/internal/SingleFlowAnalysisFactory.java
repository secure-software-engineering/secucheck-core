package de.fraunhofer.iem.secucheck.analysis.internal;

import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;

public interface SingleFlowAnalysisFactory {
	
	SingleFlowAnalysis create(TaintFlowQueryImpl flowQuery);
	
}
