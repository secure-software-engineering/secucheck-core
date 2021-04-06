package de.fraunhofer.iem.secucheck.analysis;

import de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis.SingleFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis.SingleFlowAnalysisFactory;
import de.fraunhofer.iem.secucheck.analysis.query.SecucheckTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.CompositeTaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;

import java.util.List;

public class CompositeTaintFlowAnalysisImpl implements CompositeTaintFlowAnalysis {

    private final SecucheckTaintFlowQuery flowQuery;
    private final SingleFlowAnalysisFactory analysisFactory;
    private final AnalysisResultListener resultListener;

    public CompositeTaintFlowAnalysisImpl(SecucheckTaintFlowQuery flowQuery,
                                          SingleFlowAnalysisFactory analysisFactory,
                                          AnalysisResultListener resultListener)
            throws Exception {
        this.flowQuery = flowQuery;
        this.analysisFactory = analysisFactory;
        this.resultListener = resultListener;
    }

    @Override
    public CompositeTaintFlowQueryResult run() throws Exception {

        CompositeTaintFlowQueryResult result = new CompositeTaintFlowQueryResult();

        List<TaintFlowImpl> flows = flowQuery.getTaintFlows();

        for (TaintFlowImpl originalFlow : flows) {

            if (this.resultListener != null && this.resultListener.isCancelled()) {
                break;
            }

            SingleFlowAnalysis analysis = analysisFactory.create(originalFlow);
            TaintFlowQueryResult returnResult = analysis.run();

            if (returnResult.size() == 0) {
                result.clear();
                break;
            }

            if (this.resultListener != null) {
                this.resultListener.reportFlowResult(returnResult);
            }
            result.addResult((TaintFlowImpl) originalFlow, returnResult);
        }

        return result;

    }
}