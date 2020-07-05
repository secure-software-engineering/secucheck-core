package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.ArrayList;
import java.util.List;

public final class CompositeTaintFlowQueryImpl implements CompositeTaintFlowQuery {
	
	private final List<TaintFlowQuery> taintFlowQueries;
	
	public CompositeTaintFlowQueryImpl() { 
		this.taintFlowQueries = new ArrayList<TaintFlowQuery>();
	}
	
	public void addQuery(TaintFlowQuery query) {
		this.taintFlowQueries.add(query);
	}
	
	@Override
	public List<TaintFlowQuery> getTaintFlowQueries() {
		return this.taintFlowQueries;
	}
	
	@Override
	public int getReportLocation() {
		return 0;
	}
	
	@Override
	public String getReportMessage() {
		return null;
	}
}
