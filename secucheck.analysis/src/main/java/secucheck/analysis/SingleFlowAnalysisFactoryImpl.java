package secucheck.analysis;

import secucheck.analysis.SingleFlowAnalysis.SingleFlowAnalysis;
import secucheck.analysis.SingleFlowAnalysis.SingleFlowAnalysisFactory;
import secucheck.analysis.configuration.SecucheckAnalysisConfiguration;
import secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.BoomerangSingleFlowAnalysis;
import secucheck.analysis.implementation.SingleFlowTaintAnalysis.FlowDroidSolver.FlowDroidSingleFlowAnalysis;
import secucheck.analysis.query.Solver;
import secucheck.analysis.query.TaintFlowImpl;

/**
 * This implements the SingleFlowAnalysisFactory. This calls the respective solver to solve the each TaintFlow
 */
public class SingleFlowAnalysisFactoryImpl implements SingleFlowAnalysisFactory {

    private Solver solver;
    private SecucheckAnalysisConfiguration configuration;

    public SingleFlowAnalysisFactoryImpl(Solver solver, SecucheckAnalysisConfiguration configuration) {
        this.solver = solver;
        this.configuration = configuration;
    }

    @Override
    public SingleFlowAnalysis create(TaintFlowImpl flowQuery) {

        switch (solver) {
            case BOOMERANG3:
                return new BoomerangSingleFlowAnalysis(flowQuery, this.configuration);

            case FLOWDROID:
                return new FlowDroidSingleFlowAnalysis(flowQuery, this.configuration);

            default:
                return null;
        }
    }
}
