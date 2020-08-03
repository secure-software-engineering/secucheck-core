package de.fraunhofer.iem.secucheck.analysis.result;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;

public final class CompositeTaintFlowQueryResult implements AnalysisResult {

	private final Map<TaintFlowQueryImpl, TaintFlowQueryResult> results;
	
	public CompositeTaintFlowQueryResult(){
		this.results = new HashMap<TaintFlowQueryImpl, TaintFlowQueryResult>();
	}
	
	public void addResult(TaintFlowQueryImpl flowQuery, TaintFlowQueryResult result) {
		this.results.put(flowQuery, result);
	}
	
	public Map<TaintFlowQueryImpl, TaintFlowQueryResult> getResults(){
		return this.results;
	}

	@Override
	public int size() {
		return this.results.size();
	}

	@Override
	public void clear() {
		this.results.clear();
	}
}
