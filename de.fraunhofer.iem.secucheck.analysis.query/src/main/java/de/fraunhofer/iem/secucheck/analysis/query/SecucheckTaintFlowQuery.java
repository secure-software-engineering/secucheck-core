package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.datastructures.Copyable;

/**
 * Interface for the CompositeTaintFlowQuery. This contains the complete query---TaintFlows, ReportLocation as well as ReportMessage.
 * This is copyable.
 */
public interface SecucheckTaintFlowQuery extends Copyable<SecucheckTaintFlowQuery> {
    /**
     * Returns the report location.
     *
     * @return Report location
     */
    ReportSite getReportLocation();

    /**
     * Returns the report message
     *
     * @return Report message
     */
    String getReportMessage();

    /**
     * Returns the Taintflows
     *
     * @return Taintflows
     */
    List<TaintFlowImpl> getTaintFlows();

    /**
     * Setter for report location
     *
     * @param loc report location
     */
    void setReportLocation(ReportSite loc);

    /**
     * setter for report message
     *
     * @param message report message
     */
    void setReportMessage(String message);

    /**
     * Returns the ID of the TaintFlowQuery
     *
     * @return ID of the TaintFlowQuery
     */
    String getId();
}
