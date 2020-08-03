package de.fraunhofer.iem.secucheck.analysis;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;

public interface SecucheckAnalysis {	
	
	// Maybe split setting soot class path into
	// 1. Set the needed jars call.
	// 2. Set the needed classes' binary call.

	void setSootClassPath(String sootClassPath);
	void setAnalysisClasses(List<String> canonicalClassNames);
	void setListener(AnalysisResultListener resultListener);
	SecucheckTaintAnalysisResult run(List<? super CompositeTaintFlowQueryImpl> flowQueries);

}
