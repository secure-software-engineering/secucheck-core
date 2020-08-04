package de.fraunhofer.iem.secucheck.analysis.serializable.result;

import de.fraunhofer.iem.secucheck.analysis.result.CompositeTaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.AnalysisMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.MessageType;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.ReportType;

public final class ListenerResult extends ProcessMessage implements AnalysisMessage {
	
	private ReportType reportType;
	private TaintFlowQueryResult singleResult;
	private CompositeTaintFlowQueryResult compositeResult;
	private SecucheckTaintAnalysisResult completeResult;
	
	public ListenerResult() { super.messageType = getMessageType();}
	
	public void setReportType(ReportType reportType) {
		this.reportType = reportType;
	}
	
	public void setCompleteResult(SecucheckTaintAnalysisResult completeResult) {
		this.completeResult = completeResult;
	}
	
	public void setSingleResult(TaintFlowQueryResult singleResult) {
		this.singleResult = singleResult;
	}
	
	public void setCompositeResult(CompositeTaintFlowQueryResult compositeResult) {
		this.compositeResult = compositeResult;
	}
	
	public ReportType getReportType() {
		return this.reportType;
	}
	
	public MessageType getMessageType() {
		return MessageType.ListenerResult;
	}
	
	public SecucheckTaintAnalysisResult getCompleteResult() {
		return completeResult;
	}
	
	public CompositeTaintFlowQueryResult getCompositeResult() {
		return compositeResult;
	}
	
	public TaintFlowQueryResult getSingleResult() {
		return singleResult;
	}
}
