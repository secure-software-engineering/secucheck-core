package de.fraunhofer.iem.secucheck.analysis.result;

public interface AnalysisResultListener {
	public boolean isCancelled();	
	
	public void reportCompleteResult(AnalysisResult result);
	public void reportCompositeFlowResult(AnalysisResult result);
	public void reportFlowResult(AnalysisResult result);
}