package de.fraunhofer.iem.secucheck.analysis.internal;

import boomerang.scene.jimple.SootCallGraph;
import de.fraunhofer.iem.secucheck.analysis.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.query.Solver;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;

public class SingleFlowAnalysisFactoryImpl implements SingleFlowAnalysisFactory {
	
	private Solver solver;
	private SootCallGraph sootCallGraph;
	private SecucheckAnalysisConfiguration configuration;
	
	public SingleFlowAnalysisFactoryImpl(Solver solver, SootCallGraph sootCallGraph,
			SecucheckAnalysisConfiguration configuration){
		this.solver = solver;
		this.sootCallGraph = sootCallGraph;
		this.configuration = configuration;
	}
	
	@Override
	public SingleFlowAnalysis create(TaintFlowQueryImpl flowQuery) {
		
		switch (solver) {
			case BOOMERANG3:
				return new BoomerangSingleFlowAnalysis(flowQuery, this.sootCallGraph, this.configuration);

			case FLOWDROID:
				return new FlowDroidSingleFlowAnalysis();
				
			default:
				return null;
		}		
	}
}
