package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

public interface CompositeTaintFlowQuery {
	List<TaintFlowQuery> getTaintFlowQueries();
}
