package de.fraunhofer.iem.secucheck.analysis;

import de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis.SingleFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis.SingleFlowAnalysisFactory;
import de.fraunhofer.iem.secucheck.analysis.configuration.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.BoomerangSingleFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.FlowDroidSolver.FlowDroidSingleFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.query.Solver;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;

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
