package de.fraunhofer.iem.secucheck.analysis;

import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.AnalysisResult;

/**
 * Top level Analysis.
 */
public interface Analysis {
    AnalysisResult run();
}
