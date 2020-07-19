package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.ArrayList;
import java.util.List;

public final class CompositeTaintFlowQueryImpl implements CompositeTaintFlowQuery {
	
	private final List<TaintFlowQuery> taintFlowQueries;

	private int reportLocation;
	private String message;
	
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
		return this.reportLocation;
	}
	
	@Override
	public String getReportMessage() {
		return this.message;
	}
	
	@Override
	public void setReportLocation(int loc) {
		this.reportLocation = loc;
	}
	
	@Override
	public void setReportMessage(String message) {
		this.message = message;
	}
	
	@Override
	public void copyTo(CompositeTaintFlowQuery copy) {
		copy.setReportLocation(this.getReportLocation());
		copy.setReportMessage(this.getReportMessage());
		copy.getTaintFlowQueries().addAll(this.getTaintFlowQueries());
	}
}
