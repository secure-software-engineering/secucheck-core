package de.fraunhofer.iem.secucheck.analysis.result;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;

public final class CompositeTaintFlowQueryResult implements AnalysisResult {

	private final Map<TaintFlowQuery, AnalysisResult> results;
	
	public CompositeTaintFlowQueryResult(){
		this.results = new HashMap<TaintFlowQuery, AnalysisResult>();
	}
	
	public void addResult(TaintFlowQuery flowQuery, AnalysisResult result) {
		this.results.put(flowQuery, result);
	}
	
	public Iterator<Entry<TaintFlowQuery, AnalysisResult>> getResults(){
		return this.results.entrySet().iterator();
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
