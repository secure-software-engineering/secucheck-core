package de.fraunhofer.iem.secucheck.analysis.internal;

import java.util.List;

import boomerang.callgraph.ObservableICFG;
import boomerang.callgraph.ObservableStaticICFG;
import de.fraunhofer.iem.secucheck.analysis.Analysis;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.CompositeTaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.toolkits.ide.icfg.BiDiInterproceduralCFG;

public class CompositeTaintFlowAnalysis implements Analysis {

	private final CompositeTaintFlowQuery flowQuery;
	private final ObservableICFG<Unit, SootMethod> icfg;
	private final AnalysisResultListener resultListener;
	
	public CompositeTaintFlowAnalysis(BiDiInterproceduralCFG<Unit, SootMethod> icfg, 
			CompositeTaintFlowQuery flowQuery, AnalysisResultListener resultListener) 
					throws Exception {
		this.flowQuery = flowQuery;
		this.icfg = new ObservableStaticICFG(icfg);
		this.resultListener = resultListener;
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
		List<TaintFlowQueryImpl> flows = flowQuery.getTaintFlowQueries();
		for (TaintFlowQueryImpl originalFlow : flows) {
			if (this.resultListener != null && this.resultListener.isCancelled()) {
				break;
			}
			Analysis analysis = new SingleFlowAnalysis(originalFlow, icfg, this.resultListener);
			AnalysisResult retResult = analysis.run();
			if (retResult.size() == 0) {
				result.clear();
				break;
			}
			if (this.resultListener != null) {
				this.resultListener.reportFlowResult(retResult);
			}
			result.addResult((TaintFlowQueryImpl) originalFlow, (TaintFlowQueryResult) retResult);		
		}		
		return result;		
	}	
}
