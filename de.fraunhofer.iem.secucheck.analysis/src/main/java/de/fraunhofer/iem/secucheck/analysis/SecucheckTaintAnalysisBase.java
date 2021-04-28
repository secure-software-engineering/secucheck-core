package de.fraunhofer.iem.secucheck.analysis;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

import de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis.SingleFlowAnalysisFactory;
import de.fraunhofer.iem.secucheck.analysis.configuration.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.query.SecucheckTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;

/**
 * First level implementation of the SecucheckAnalysis. This validates TaintFlowQuery, SecucheckConfiguration and run the analysis.
 */
public abstract class SecucheckTaintAnalysisBase implements SecucheckAnalysis {

    protected final ReentrantLock lock;
    protected SecucheckAnalysisConfiguration configuration;

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
    public SecucheckTaintAnalysisResult run(List<SecucheckTaintFlowQueryImpl> flowQueries)
            throws Exception {
        Utility.ValidateSecucheckTaintFlowQueries(flowQueries);  // Validate the TaintFlowQuery before starting analysis
        Utility.ValidateConfigruation(this.configuration);  // Validate the SecucheckAnalysisConfiguration

        // Lock and run the analysis
        lock.lock();

        try {
            return executeAnalysis(flowQueries);
        } finally {
            lock.unlock();  // Release the lock for next run
        }
    }

    /**
     * This method calls the SecucheckTaintFlowQueryAnalysis for each TaintFlowQuery
     *
     * @param flowQueries List of TaintFlowQueries
     * @return complete SecucheckTaintAnalysis
     * @throws Exception Any exception
     */
    private SecucheckTaintAnalysisResult executeAnalysis(List<SecucheckTaintFlowQueryImpl> flowQueries)
            throws Exception {
        SingleFlowAnalysisFactory analysisFactory =
                new SingleFlowAnalysisFactoryImpl(this.configuration.getSolver(), this.configuration);

        SecucheckTaintAnalysisResult result = new SecucheckTaintAnalysisResult();

        long startTime = System.currentTimeMillis();    // Save the start time

        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        result.setStartTime(dateTimeFormatter.format(LocalDateTime.now()));

        for (SecucheckTaintFlowQueryImpl flowQuery : flowQueries) { // for each TaintFlowQuery

            if (this.configuration.getListener() != null &&
                    this.configuration.getListener().isCancelled()) {   // Analysis is cancelled by the client then stop the analysis
                break;
            }

            SecucheckTaintFlowQueryAnalysis analysis = new SecucheckTaintFlowQueryAnalysisImpl(flowQuery,
                    analysisFactory, this.configuration.getListener());

            SecucheckTaintFlowQueryResult singleResult = analysis.run();

            if (singleResult.size() != 0) {
                result.addResult(flowQuery, singleResult);
            }

            if (this.configuration.getListener() != null) {
                this.configuration.getListener()
                        .reportSecucheckTaintFlowQueryResult((SecucheckTaintFlowQueryResult) singleResult);
            }
        }

        result.setEndTime(dateTimeFormatter.format(LocalDateTime.now()));

        long endTime = System.currentTimeMillis(); // Record the end time

        result.setExecutionTime(endTime - startTime);
        return result;
    }

}
