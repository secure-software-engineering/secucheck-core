package de.fraunhofer.iem.secucheck.analysis;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;

public interface SecucheckAnalysis {	
	
	void setSootClassPath(String sootClassPath);
	void setAnalysisClasses(List<String> canonicalClassNames);
	void setListener(AnalysisResultListener resultListener);
	SecucheckTaintAnalysisResult run(List<CompositeTaintFlowQuery> flowQueries);
	
}
