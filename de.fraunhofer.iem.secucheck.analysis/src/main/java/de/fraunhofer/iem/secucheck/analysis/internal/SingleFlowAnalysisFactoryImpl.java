package de.fraunhofer.iem.secucheck.analysis.internal;

import boomerang.scene.jimple.SootCallGraph;
import de.fraunhofer.iem.secucheck.analysis.query.Solver;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;

public class SingleFlowAnalysisFactoryImpl implements SingleFlowAnalysisFactory {
	
	private Solver solver;
	private SootCallGraph sootCallGraph;
	private AnalysisResultListener resultListener;
	
	public SingleFlowAnalysisFactoryImpl(Solver solver, SootCallGraph sootCallGraph,
			AnalysisResultListener resultListener){
		this.solver = solver;
		this.sootCallGraph = sootCallGraph;
		this.resultListener = resultListener;
	}
	
	@Override
	public SingleFlowAnalysis create(TaintFlowQueryImpl flowQuery) {
		
		switch (solver) {
			case Boomerang:
				return new BoomerangSingleFlowAnalysis(flowQuery, this.sootCallGraph, this.resultListener);

			case FlowDroid:
				return new FlowDroidSingleFlowAnalysis();
				
			default:
				return null;
		}		
	}
}
