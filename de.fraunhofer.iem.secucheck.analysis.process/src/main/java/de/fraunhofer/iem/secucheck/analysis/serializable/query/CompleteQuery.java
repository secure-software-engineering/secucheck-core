package de.fraunhofer.iem.secucheck.analysis.serializable.query;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.serializable.AnalysisMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.MessageType;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessage;

public final class CompleteQuery extends ProcessMessage implements AnalysisMessage {
	
	private boolean hasResultListener;
	private String sootClassPath;
	private List<String> canonicalClasses;
	private List<? super CompositeTaintFlowQueryImpl> flowQueries;
	
	public CompleteQuery() { }
	
	public CompleteQuery(String sootClassPath, List<String> canonicalClassNames,
			List<? super CompositeTaintFlowQueryImpl> flowQueries, boolean hasResultListener) {
		super.messageType = getMessageType();
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
	
	public List<? super CompositeTaintFlowQueryImpl> getFlowQueries() {
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
	
	public void setFlowQueries(List<CompositeTaintFlowQueryImpl> flowQueries) {
		this.flowQueries = flowQueries;
	}
	
	public void setHasResultListener(boolean hasResultListener) {
		this.hasResultListener = hasResultListener;
	}
	
	public void setSootClassPath(String sootClassPath) {
		this.sootClassPath = sootClassPath;
	}	
}