package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis;

import boomerang.Boomerang;
import boomerang.scene.AnalysisScope;
import boomerang.scene.SootDataFlowScope;
import boomerang.scene.jimple.SootCallGraph;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.TaintAnalysisOptions;
import soot.Scene;

public class SingleFlowBoomerang extends Boomerang { 
	
	private final AnalysisScope analysisScope;
	private final SootCallGraph sootCallGraph;
	
	public SingleFlowBoomerang(AnalysisScope analysisScope, 
			SootCallGraph sootCallGraph, TaintAnalysisOptions options){
		super(sootCallGraph, SootDataFlowScope.make(Scene.v()), options);
		this.analysisScope = analysisScope;
		this.sootCallGraph = sootCallGraph;
	}
}
