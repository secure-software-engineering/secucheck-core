package de.fraunhofer.iem.secucheck.ftql.fluentInterface.query;

import de.fraunhofer.iem.secucheck.ftql.dsl.QueriesSet;
import de.fraunhofer.iem.secucheck.ftql.dsl.constants.LOCATION;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.taintflowpack.TaintFlow;

import java.util.List;

/**
 * Interface for TaintFlowQuery
 */
public interface TaintFlowQuery extends FluentTQLSpecification {
    /**
     * Returns the List of TaintFlow
     *
     * @return List of TaintFlow
     */
    List<TaintFlow> getTaintFlows();

    /**
     * Returns the Report Message
     *
     * @return Report Message
     */
    String getReportMessage();

    /**
     * Returns the QueriesSet
     *
     * @return QueriesSet
     */
    QueriesSet getQueriesSet();

    /**
     * Returns the Report Location
     *
     * @return Report Location
     */
    LOCATION getReportLocation();
}
