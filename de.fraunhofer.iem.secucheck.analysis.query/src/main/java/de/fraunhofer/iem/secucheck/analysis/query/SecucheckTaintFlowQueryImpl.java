package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of the CompositeTaintFlowQuery. This is copyable.
 */
public final class SecucheckTaintFlowQueryImpl implements SecucheckTaintFlowQuery {

    private final List<TaintFlowImpl> taintFlowQueries;
    private final String id;
    private List<EntryPoint> entryPoints;
    private String message;
    private ReportSite reportLocation;
    private boolean DSLEntryPoints;

    public SecucheckTaintFlowQueryImpl(String id) {
        this.taintFlowQueries = new ArrayList<TaintFlowImpl>();
        this.id = id;
        this.DSLEntryPoints = false;
    }

    public void addQuery(TaintFlowImpl query) {
        this.taintFlowQueries.add(query);
    }

    public List<TaintFlowImpl> getTaintFlows() {
        return taintFlowQueries;
    }
    
    @Override
	public List<EntryPoint> getEntryPoints() {
		return this.entryPoints;
	}
    
    public void setEntryPoint(List<EntryPoint> entryPoints) {
    	this.entryPoints = entryPoints;
    }
    
    public void addEntryPoint(EntryPoint entryPoint) {
    	this.entryPoints.add(entryPoint);
    }

    @Override
    public ReportSite getReportLocation() {
        return this.reportLocation;
    }
    
    @Override
    public void setReportLocation(ReportSite loc) {
        this.reportLocation = loc;
    }

    @Override
    public String getReportMessage() {
        return this.message;
    }

    @Override
    public void setReportMessage(String message) {
        this.message = message;
    }
    
    public void setDSLEntryPoints(boolean DSLEntryPoints) {
    	this.DSLEntryPoints = DSLEntryPoints;
    }
    
    @Override
	public boolean isDSLEntryPoints() {
		return this.DSLEntryPoints;
	}

    @Override
    public void copyTo(SecucheckTaintFlowQuery copy) {
        copy.setReportLocation(this.getReportLocation());
        copy.setReportMessage(this.getReportMessage());
        copy.getTaintFlows().addAll(this.getTaintFlows());
        copy.getEntryPoints().addAll(this.getEntryPoints());
    }

    @Override
    public String getId() {
        return id;
    }
    
}
