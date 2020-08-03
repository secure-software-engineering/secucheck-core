package de.fraunhofer.iem.secucheck.analysis.result;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

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
		return 0;
	}

	@Override
	public void clear() {
		results.clear();
	}
}
