package de.fraunhofer.iem.secucheck.analysis.result;

import java.util.HashMap;
import java.util.Map;

import boomerang.Query;
import de.fraunhofer.iem.secucheck.analysis.datastructures.Pair;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;

public class TaintFlowQueryResult implements AnalysisResult {
	
	private final Map<TaintFlowQueryImpl, Pair<Query,Query>> resultMap;
	
	public TaintFlowQueryResult(){
		this.resultMap = new HashMap<TaintFlowQueryImpl, Pair<Query,Query>>();
	}
	
	public void addQueryResultPair(TaintFlowQueryImpl query,
			Pair<Query,Query> result) {
		this.resultMap.put(query, result);
	}
	
	public void addQueryResultPairs(
			Map<TaintFlowQueryImpl, Pair<Query,Query>> pairs) {
		this.resultMap.putAll(pairs);
	}
	
	public void clear() {
		this.resultMap.clear();
	}
	
	@Override
	public int size() {
		return this.resultMap.size();
	}
	
	public Map<TaintFlowQueryImpl, Pair<Query,Query>> getQueryResultMap(){
		return this.resultMap;
	}
}
