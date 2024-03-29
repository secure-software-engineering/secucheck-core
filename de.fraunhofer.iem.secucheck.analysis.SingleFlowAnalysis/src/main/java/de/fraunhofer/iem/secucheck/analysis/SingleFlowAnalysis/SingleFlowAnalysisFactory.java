package de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis;

import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;

/**
 * Factory to create respective solver's single Taint flow analysis. Currently Boomerang 3 and Flowdroid solvers are available.
 */
public interface SingleFlowAnalysisFactory {
    SingleFlowAnalysis create(TaintFlowImpl flowQuery);
}
