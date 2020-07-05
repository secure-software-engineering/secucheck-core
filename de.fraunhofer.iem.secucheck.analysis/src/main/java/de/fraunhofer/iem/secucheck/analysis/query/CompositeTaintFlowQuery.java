package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

public interface CompositeTaintFlowQuery {
	int getReportLocation();
	String getReportMessage();
	List<TaintFlowQuery> getTaintFlowQueries();
}
