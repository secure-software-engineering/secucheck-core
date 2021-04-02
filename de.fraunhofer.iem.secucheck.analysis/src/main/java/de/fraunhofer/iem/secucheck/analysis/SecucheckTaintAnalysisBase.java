package de.fraunhofer.iem.secucheck.analysis;

import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.CompositeTaintFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.CompositeTaintFlowAnalysisImpl;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.SingleFlowAnalysisFactory;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.SingleFlowAnalysisFactoryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.CompositeTaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.SecucheckTaintAnalysisResult;

/**
 * First level implementation of the SecucheckAnalysis. This valideates TaintFlowQuery, SecucheckConfiguration and run the analysis.
 */
public abstract class SecucheckTaintAnalysisBase implements SecucheckAnalysis {

    protected final ReentrantLock lock;
    protected SecucheckAnalysisConfiguration configuration;
    protected long analysisTime;

    public SecucheckTaintAnalysisBase(SecucheckAnalysisConfiguration configuration) {
        this.lock = new ReentrantLock();
        this.configuration = configuration;
    }

    @Override
    public void setConfiguration(SecucheckAnalysisConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public SecucheckAnalysisConfiguration getConfiguration() {
        return this.configuration;
    }

    @Override
    public SecucheckTaintAnalysisResult run(List<CompositeTaintFlowQueryImpl> flowQueries)
            throws Exception {
        Utility.ValidateCompositeFlowQueries(flowQueries);
        Utility.ValidateConfigruation(this.configuration);
        lock.lock();
        try {
            return executeAnalysis(flowQueries);
        } finally {
            lock.unlock();
        }
    }

    private SecucheckTaintAnalysisResult executeAnalysis(List<CompositeTaintFlowQueryImpl> flowQueries)
            throws Exception {

        long startTime = System.currentTimeMillis();

        SingleFlowAnalysisFactory analysisFactory =
                new SingleFlowAnalysisFactoryImpl(this.configuration.getSolver(), this.configuration);

        SecucheckTaintAnalysisResult result = new SecucheckTaintAnalysisResult();

        for (CompositeTaintFlowQueryImpl flowQuery : flowQueries) {

            if (this.configuration.getListener() != null &&
                    this.configuration.getListener().isCancelled()) {
                break;
            }

            CompositeTaintFlowAnalysis analysis = new CompositeTaintFlowAnalysisImpl(flowQuery,
                    analysisFactory, this.configuration.getListener());

            CompositeTaintFlowQueryResult singleResult = analysis.run();

            if (singleResult.size() != 0) {
                result.addResult(flowQuery, singleResult);
            }

            if (this.configuration.getListener() != null) {
                this.configuration.getListener()
                        .reportCompositeFlowResult((CompositeTaintFlowQueryResult) singleResult);
            }
        }

        long endTime = System.currentTimeMillis();

        analysisTime = endTime - startTime;

        return result;
    }

}
