package de.fraunhofer.iem.secucheck.analysis.serializable.query;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.serializable.AnalysisMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.MessageType;

public final class CompleteQuery implements AnalysisMessage {
	private String sootClassPath;
	private List<String> canonicalClasses;
	private boolean hasResultListener;
	private List<CompositeTaintFlowQuery> flowQueries;
	
	public CompleteQuery(String sootClassPath, List<String> canonicalClassNames,
			List<CompositeTaintFlowQuery> flowQueries, boolean hasResultListener) {
		this.sootClassPath = sootClassPath;
		this.flowQueries = flowQueries;
		this.canonicalClasses = canonicalClassNames;
		this.hasResultListener = hasResultListener;
	}
	
	public MessageType getMessageType() {
		return MessageType.CompleteQuery;
	}
	
	public List<String> getCanonicalClasses() {
		return canonicalClasses;
	}
	
	public List<CompositeTaintFlowQuery> getFlowQueries() {
		return flowQueries;
	}
	
	public boolean hasResultListener() {
		return hasResultListener;
	}
	
	public String getSootClassPath() {
		return sootClassPath;
	}
	
	public void setCanonicalClasses(List<String> canonicalClasses) {
		this.canonicalClasses = canonicalClasses;
	}
	
	public void setFlowQueries(List<CompositeTaintFlowQuery> flowQueries) {
		this.flowQueries = flowQueries;
	}
	
	public void setHasResultListener(boolean hasResultListener) {
		this.hasResultListener = hasResultListener;
	}
	
	public void setSootClassPath(String sootClassPath) {
		this.sootClassPath = sootClassPath;
	}	
}
