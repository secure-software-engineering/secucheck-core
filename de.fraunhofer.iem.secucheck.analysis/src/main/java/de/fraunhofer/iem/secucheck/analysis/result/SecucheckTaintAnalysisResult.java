package de.fraunhofer.iem.secucheck.analysis.result;

import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;

public final class SecucheckTaintAnalysisResult implements AnalysisResult {
	
	private List<DifferentTypedPair<CompositeTaintFlowQueryImpl, CompositeTaintFlowQueryResult>> results;
	
	public SecucheckTaintAnalysisResult()
	{
		this.results = new ArrayList<DifferentTypedPair<CompositeTaintFlowQueryImpl, CompositeTaintFlowQueryResult>>();
	}
	
	public void addResult(CompositeTaintFlowQueryImpl compositeQuery, CompositeTaintFlowQueryResult result) {		
		this.results.add(
				new DifferentTypedPair<CompositeTaintFlowQueryImpl, CompositeTaintFlowQueryResult>
					(compositeQuery, result));
	}

	public List<DifferentTypedPair<CompositeTaintFlowQueryImpl, CompositeTaintFlowQueryResult>> getResults(){
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
