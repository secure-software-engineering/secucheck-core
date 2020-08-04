package de.fraunhofer.iem.secucheck.analysis.result;

import java.util.HashMap;
import java.util.Map;

import de.fraunhofer.iem.secucheck.analysis.datastructures.Pair;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;

public class TaintFlowQueryResult implements AnalysisResult {
	
	private final Map<TaintFlowQueryImpl, Pair<LocationDetails,LocationDetails>> resultMap;
	
	public TaintFlowQueryResult(){
		this.resultMap = new HashMap<TaintFlowQueryImpl, Pair<LocationDetails,LocationDetails>>();
	}
	
	public void addQueryResultPair(TaintFlowQueryImpl query,
			Pair<LocationDetails,LocationDetails> result) {
		this.resultMap.put(query, result);
	}
	
	public void addQueryResultPairs(
			Map<TaintFlowQueryImpl, Pair<LocationDetails,LocationDetails>> pairs) {
		this.resultMap.putAll(pairs);
	}
	
	public void clear() {
		this.resultMap.clear();
	}
	
	@Override
	public int size() {
		return this.resultMap.size();
	}
	
	public Map<TaintFlowQueryImpl, Pair<LocationDetails,LocationDetails>> getQueryResultMap(){
		return this.resultMap;
	}
}
