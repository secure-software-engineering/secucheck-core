package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.datastructures.Copyable;

public interface CompositeTaintFlowQuery extends Copyable<CompositeTaintFlowQuery> {
    ReportSite getReportLocation();

    String getReportMessage();

    List<TaintFlowQueryImpl> getTaintFlowQueries();

    void setReportLocation(ReportSite loc);

    void setReportMessage(String message);
}
