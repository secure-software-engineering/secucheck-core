package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis;

import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.SingleFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;

public interface SingleFlowAnalysisFactory {
	
	SingleFlowAnalysis create(TaintFlowQueryImpl flowQuery);
	
}
