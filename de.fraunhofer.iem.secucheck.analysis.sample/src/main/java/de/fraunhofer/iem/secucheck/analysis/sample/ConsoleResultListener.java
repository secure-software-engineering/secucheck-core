package de.fraunhofer.iem.secucheck.analysis.sample;

import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.CompositeTaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;

public class ConsoleResultListener implements AnalysisResultListener {
	public void reportFlowResult(TaintFlowQueryResult result) {
		System.out.println();
		System.out.println("Recieved single flow result, size:" + result.size());
	}
	
	public void reportCompositeFlowResult(CompositeTaintFlowQueryResult result) {
		System.out.println();
		System.out.println("Recieved composite flow result, size:" + result.size());
	}
	
	public void reportCompleteResult(SecucheckTaintAnalysisResult result) {
		System.out.println();
		System.out.println("Recieved complete result, size:" + result.size());
	}
	
	public boolean isCancelled() {
		return false;
	}
}
