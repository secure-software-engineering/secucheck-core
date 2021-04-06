package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of the CompositeTaintFlowQuery. This is copyable.
 */
public final class SecucheckTaintFlowQueryImpl implements SecucheckTaintFlowQuery {

    private final List<TaintFlowImpl> taintFlowQueries;

    private String message;
    private ReportSite reportLocation;

    public SecucheckTaintFlowQueryImpl() {
        this.taintFlowQueries = new ArrayList<TaintFlowImpl>();
    }

    public void addQuery(TaintFlowImpl query) {
        this.taintFlowQueries.add(query);
    }

    public List<TaintFlowImpl> getTaintFlows() {
        return taintFlowQueries;
    }

    @Override
    public ReportSite getReportLocation() {
        return this.reportLocation;
    }

    @Override
    public String getReportMessage() {
        return this.message;
    }

    @Override
    public void setReportLocation(ReportSite loc) {
        this.reportLocation = loc;
    }

    @Override
    public void setReportMessage(String message) {
        this.message = message;
    }

    @Override
    public void copyTo(SecucheckTaintFlowQuery copy) {
        copy.setReportLocation(this.getReportLocation());
        copy.setReportMessage(this.getReportMessage());
        copy.getTaintFlows().addAll(this.getTaintFlows());
    }
}
