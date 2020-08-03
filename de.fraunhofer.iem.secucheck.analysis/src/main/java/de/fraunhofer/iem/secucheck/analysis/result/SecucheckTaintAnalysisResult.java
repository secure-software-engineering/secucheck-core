package de.fraunhofer.iem.secucheck.analysis.result;

import java.util.HashMap;
import java.util.Map;


import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;

public final class SecucheckTaintAnalysisResult implements AnalysisResult {
	
	private Map<CompositeTaintFlowQuery, CompositeTaintFlowQueryResult> results;
	
	public SecucheckTaintAnalysisResult()
	{
		this.results = new HashMap<CompositeTaintFlowQuery, CompositeTaintFlowQueryResult>();
	}
	
	public void addResult(CompositeTaintFlowQuery compositeQuery, CompositeTaintFlowQueryResult result) {		
		this.results.put(compositeQuery, result);
	}

	public Map<CompositeTaintFlowQuery, CompositeTaintFlowQueryResult> getResults(){
		return this.results;
	}

	@Override
	public int size() {
		return this.results.size();
	}

	@Override
	public void clear() {
		results.clear();
	}
}
