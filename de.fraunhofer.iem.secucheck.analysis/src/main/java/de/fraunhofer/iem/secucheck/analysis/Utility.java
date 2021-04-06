package de.fraunhofer.iem.secucheck.analysis;

import de.fraunhofer.iem.secucheck.analysis.configuration.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.query.SecucheckTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.SecucheckTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlow;

import java.util.List;

/**
 * Utility class
 */
class Utility {

    /**
     * This method validates the given list of TaintFlowQueries
     *
     * @param flowQueries List of TaintFlowQueries
     * @throws Exception Any exception
     */
    public static void ValidateSecucheckTaintFlowQueries(List<? super SecucheckTaintFlowQueryImpl> flowQueries)
            throws Exception {
        for (Object object : flowQueries) {

            if (object == null)
                throw new Exception("Please specify not null composite flow query.");

            SecucheckTaintFlowQuery secucheckTaintFlowQuery = (SecucheckTaintFlowQuery) object;
            ValidateSingleSecucheckTaintFlowQuery(secucheckTaintFlowQuery);
        }
    }

    /**
     * This method validates single TaintFlowQuery
     *
     * @param flowQuery Single TaintFlowQuery
     * @throws Exception Any exception
     */
    public static void ValidateSingleSecucheckTaintFlowQuery(SecucheckTaintFlowQuery flowQuery)
            throws Exception {
        for (TaintFlow singleFlow : flowQuery.getTaintFlows()) {

            if (singleFlow == null)
                throw new Exception("Please specify not null single flow query.");

            ValidateSingleTaintFlow(singleFlow);
        }
    }

    /**
     * This method validates the single TaintFlow
     *
     * @param taintFlow Single TaintFlow
     * @throws Exception Any exception
     */
    public static void ValidateSingleTaintFlow(TaintFlow taintFlow) throws Exception {
        if (taintFlow.getFrom() == null || taintFlow.getFrom().size() == 0)
            throw new Exception("For a valid taint flow query there must be some source specified.");
        if (taintFlow.getTo() == null || taintFlow.getTo().size() == 0)
            throw new Exception("For a valid taint flow query there must be a sink specified.");
    }

    /**
     * This method validates the given SecucheckConfiguration from the client
     *
     * @param configuration SecuchecAnalysisConfiguration
     * @throws Exception Any exception
     */
    public static void ValidateConfigruation(SecucheckAnalysisConfiguration configuration) throws Exception {
        if (configuration == null)
            throw new Exception("The configuration for Secucheck analysis is not set.");
        if (configuration.getApplicationClassPath() == null || configuration.getApplicationClassPath().isEmpty())
            throw new Exception("The application class-path for Secucheck analysis is not set.");
        if (configuration.getAnalysisEntryPoints() == null || configuration.getAnalysisEntryPoints().size() == 0)
            throw new Exception("The entry-points for Secucheck analysis are not provided.");
    }
}
