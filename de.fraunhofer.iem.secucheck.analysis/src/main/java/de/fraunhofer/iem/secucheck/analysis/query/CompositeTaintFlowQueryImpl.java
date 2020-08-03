package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.ArrayList;
import java.util.List;

public final class CompositeTaintFlowQueryImpl implements CompositeTaintFlowQuery {
	
	private final List<TaintFlowQueryImpl> taintFlowQueries;

	private int reportLocation;
	private String message;
	
	public CompositeTaintFlowQueryImpl() { 
		this.taintFlowQueries = new ArrayList<TaintFlowQueryImpl>();
	}
	
	public void addQuery(TaintFlowQueryImpl query) {
		this.taintFlowQueries.add(query);
	}
	
	public List<TaintFlowQueryImpl> getTaintFlowQueries() {
		return taintFlowQueries;
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
