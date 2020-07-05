package de.fraunhofer.iem.secucheck.analysis.result;

import java.util.HashMap;
import java.util.Map;

import boomerang.Query;
import de.fraunhofer.iem.secucheck.analysis.datastructures.Pair;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;

public class TaintFlowQueryResult implements AnalysisResult {
	
	private final Map<TaintFlowQuery, Pair<Query,Query>> resultMap;
	
	public TaintFlowQueryResult()
	{
		resultMap = new HashMap<TaintFlowQuery, Pair<Query,Query>>();
	}
	
	public void addQueryResultPair(TaintFlowQuery query,
			Pair<Query,Query> result) {
		resultMap.put(query, result);
	}
	
	public void addQueryResultPairs(
			Map<TaintFlowQuery, Pair<Query,Query>> pairs) {
		resultMap.putAll(pairs);
	}
	
	public void clear() {
		resultMap.clear();
	}
	
	@Override
	public int size() {
		return 0;
	}
	
	public Map<TaintFlowQuery, Pair<Query,Query>> getQueryResultMap(){
		return resultMap;
	}
}
