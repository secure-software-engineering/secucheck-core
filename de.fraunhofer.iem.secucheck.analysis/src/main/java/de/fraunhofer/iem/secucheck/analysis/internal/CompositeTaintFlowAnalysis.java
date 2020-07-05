package de.fraunhofer.iem.secucheck.analysis.internal;

import boomerang.callgraph.ObservableICFG;
import boomerang.callgraph.ObservableStaticICFG;
import de.fraunhofer.iem.secucheck.analysis.Analysis;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.CompositeTaintFlowQueryResult;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.toolkits.ide.icfg.BiDiInterproceduralCFG;

public class CompositeTaintFlowAnalysis implements Analysis {

	private final CompositeTaintFlowQuery flowQuery;
	private final ObservableICFG<Unit, SootMethod> icfg;
	
	public CompositeTaintFlowAnalysis(BiDiInterproceduralCFG<Unit, SootMethod> icfg, 
			CompositeTaintFlowQuery flowQuery) {
		this.flowQuery = flowQuery;
		this.icfg = new ObservableStaticICFG(icfg);
		
		// Resolve all methods. This is necessary if a flow participant is not part of
		// the user code...
		// See: https://github.com/secure-software-engineering/secucheck/issues/11
		for (Method method : Utility.getMethods(flowQuery)) {
			Utility.getSootMethod(method);
		}
	}
	
	@Override
	public AnalysisResult run() {	
		CompositeTaintFlowQueryResult result = new CompositeTaintFlowQueryResult();
		for (TaintFlowQuery originalFlow : flowQuery.getTaintFlowQueries()) {
			Analysis analysis = new SingleFlowAnalysis(originalFlow, icfg);
			AnalysisResult retResult = analysis.run();
			if (retResult.size() == 0) {
				result.clear();
				break;
			}
			result.addResult(originalFlow, retResult);		
		}		
		return result;		
	}	
}
