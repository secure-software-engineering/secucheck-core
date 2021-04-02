package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis;

import de.fraunhofer.iem.secucheck.analysis.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.BoomerangSingleFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.FlowDroidSolver.FlowDroidSingleFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.query.Solver;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;

public class SingleFlowAnalysisFactoryImpl implements SingleFlowAnalysisFactory {

    private Solver solver;
    private SecucheckAnalysisConfiguration configuration;

    public SingleFlowAnalysisFactoryImpl(Solver solver, SecucheckAnalysisConfiguration configuration) {
        this.solver = solver;
        this.configuration = configuration;
    }

    @Override
    public SingleFlowAnalysis create(TaintFlowQueryImpl flowQuery) {

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
