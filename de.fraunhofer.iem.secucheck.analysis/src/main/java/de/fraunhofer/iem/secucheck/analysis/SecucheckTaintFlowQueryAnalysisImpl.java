package de.fraunhofer.iem.secucheck.analysis;

import de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis.SingleFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis.SingleFlowAnalysisFactory;
import de.fraunhofer.iem.secucheck.analysis.query.SecucheckTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowResult;

import java.util.List;

/**
 * Implementation of the SecucheckTaintFlowQueryAnalysis
 * <p>
 * This class iterates through the given SecucheckTaintFlowQuery and calls the solver that solves the single TaintFlow in each TaintFLowQuery.
 */
public class SecucheckTaintFlowQueryAnalysisImpl implements SecucheckTaintFlowQueryAnalysis {

    private final SecucheckTaintFlowQuery flowQuery;
    private final SingleFlowAnalysisFactory analysisFactory;
    private final AnalysisResultListener resultListener;

    public SecucheckTaintFlowQueryAnalysisImpl(SecucheckTaintFlowQuery flowQuery,
                                               SingleFlowAnalysisFactory analysisFactory,
                                               AnalysisResultListener resultListener) {
        this.flowQuery = flowQuery;
        this.analysisFactory = analysisFactory;
        this.resultListener = resultListener;
    }

    @Override
    public SecucheckTaintFlowQueryResult run() throws Exception {

        SecucheckTaintFlowQueryResult result = new SecucheckTaintFlowQueryResult();

        List<TaintFlowImpl> flows = flowQuery.getTaintFlows();

        for (TaintFlowImpl originalFlow : flows) {

            if (this.resultListener != null && this.resultListener.isCancelled()) {
                break;
            }

            SingleFlowAnalysis analysis = analysisFactory.create(originalFlow);
            TaintFlowResult returnResult = analysis.run();

            if (returnResult.size() == 0) {
                result.clear();
                break;
            }

            if (this.resultListener != null) {
                this.resultListener.reportTaintFlowResult(returnResult);
            }
            result.addResult((TaintFlowImpl) originalFlow, returnResult);
        }

        return result;

    }
}
