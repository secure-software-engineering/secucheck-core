package de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis;

import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;

public interface SingleFlowAnalysisFactory {

    SingleFlowAnalysis create(TaintFlowImpl flowQuery);

}
