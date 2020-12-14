package de.fraunhofer.iem.secucheck.analysis;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.query.OS;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;

public interface SecucheckAnalysis {	
	
	void setConfiguration(SecucheckAnalysisConfiguration configuration);
	SecucheckAnalysisConfiguration getConfiguration();
	
	SecucheckTaintAnalysisResult run
		(List<CompositeTaintFlowQueryImpl> flowQueries) 
				throws Exception;
}
