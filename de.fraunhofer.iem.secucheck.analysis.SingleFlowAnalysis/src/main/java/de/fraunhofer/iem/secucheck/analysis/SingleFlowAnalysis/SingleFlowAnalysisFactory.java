package de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;

/**
 * Factory to create respective solver's single Taint flow analysis. Currently Boomerang 3 and Flowdroid solvers are available.
 */
public interface SingleFlowAnalysisFactory {
    SingleFlowAnalysis create(TaintFlowImpl flowQuery, List<EntryPoint> entryPoints);
}
