package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.datastructures.Copyable;

public interface CompositeTaintFlowQuery extends Copyable<CompositeTaintFlowQuery> {
	
	int getReportLocation();
	String getReportMessage();
	List<TaintFlowQueryImpl> getTaintFlowQueries();
	void setReportLocation(int loc);
	void setReportMessage(String message);
}
