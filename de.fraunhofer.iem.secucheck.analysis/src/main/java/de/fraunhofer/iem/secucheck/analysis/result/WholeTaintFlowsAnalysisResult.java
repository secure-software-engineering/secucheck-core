package de.fraunhofer.iem.secucheck.analysis.result;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;

public final class WholeTaintFlowsAnalysisResult implements AnalysisResult {
	
	private final Map<CompositeTaintFlowQuery, AnalysisResult> results;
	
	public WholeTaintFlowsAnalysisResult()
	{
		this.results = new HashMap<CompositeTaintFlowQuery, AnalysisResult>();
	}
	
	public void addResult(CompositeTaintFlowQuery compositeQuery, AnalysisResult result) {
		this.results.put(compositeQuery, result);
	}
	
	public Iterator<Entry<CompositeTaintFlowQuery, AnalysisResult>> getResults(){
		return this.results.entrySet().iterator();
	}
}
