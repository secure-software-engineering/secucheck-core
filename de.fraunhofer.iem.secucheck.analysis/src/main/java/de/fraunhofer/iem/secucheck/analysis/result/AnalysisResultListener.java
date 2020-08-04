package de.fraunhofer.iem.secucheck.analysis.result;

public interface AnalysisResultListener {
	public boolean isCancelled();	
	
	public void reportCompleteResult(SecucheckTaintAnalysisResult result);
	public void reportCompositeFlowResult(CompositeTaintFlowQueryResult result);
	public void reportFlowResult(TaintFlowQueryResult result);
}