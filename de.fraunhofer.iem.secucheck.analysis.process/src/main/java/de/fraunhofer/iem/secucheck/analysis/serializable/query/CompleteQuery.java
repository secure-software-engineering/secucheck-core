package de.fraunhofer.iem.secucheck.analysis.serializable.query;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import de.fraunhofer.iem.secucheck.analysis.query.OS;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.serializable.AnalysisMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.MessageType;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessage;

public final class CompleteQuery extends ProcessMessage implements AnalysisMessage {
	
	private OS os;
	private boolean hasResultListener;
	private String appClassPath;
	private String sootClassPath;
	private List<EntryPoint> entryPoints;
	private List<CompositeTaintFlowQueryImpl> flowQueries;
	
	public CompleteQuery() { }
	
	public CompleteQuery(OS os, String appClassPath, String sootClassPath,
			List<EntryPoint> entryPoints, List<CompositeTaintFlowQueryImpl> flowQueries,
			boolean hasResultListener) {
		super.messageType = getMessageType();
		this.os = os;
		this.appClassPath = appClassPath;
		this.sootClassPath = sootClassPath;
		this.flowQueries = flowQueries;
		this.entryPoints = entryPoints;
		this.hasResultListener = hasResultListener;
	}
	
	public MessageType getMessageType() {
		return MessageType.CompleteQuery;
	}
	
	public List<EntryPoint> getAnalysisEntryPoints() {
		return entryPoints;
	}
	
	public List<CompositeTaintFlowQueryImpl> getFlowQueries() {
		return flowQueries;
	}
	
	@JsonProperty(value="hasResultListener")
	public boolean hasResultListener() {
		return hasResultListener;
	}
	
	public OS getOs() {
		return os;
	}
	
	public String getAppClassPath() {
		return appClassPath;
	}
	
	public String getSootClassPath() {
		return sootClassPath;
	}
	
	public void setAnalysisEntryPoints(List<EntryPoint> entryPoints) {
		this.entryPoints = entryPoints;
	}
	
	public void setFlowQueries(List<CompositeTaintFlowQueryImpl> flowQueries) {
		this.flowQueries = flowQueries;
	}
	
	public void setHasResultListener(boolean hasResultListener) {
		this.hasResultListener = hasResultListener;
	}
	
	public void setOs(OS os) {
		this.os = os;
	}
	
	public void setAppClassPath(String appClassPath) {
		this.appClassPath = appClassPath;
	}
	
	public void setSootClassPath(String sootClassPath) {
		this.sootClassPath = sootClassPath;
	}
	
	public void setEntryPoints(List<EntryPoint> entryPoints) {
		this.entryPoints = entryPoints;
	}
}