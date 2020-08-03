package de.fraunhofer.iem.secucheck.analysis.serializable.result;

import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.AnalysisMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.MessageType;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.ReportType;

public final class ListenerResult extends ProcessMessage implements AnalysisMessage {
	
	private ReportType reportType;
	private AnalysisResult result;
	
	public ListenerResult() {
		super.messageType = getMessageType();
	}
	
	public void setReportType(ReportType reportType) {
		this.reportType = reportType;
	}
	
	public ReportType getReportType() {
		return this.reportType;
	}
	
	public AnalysisResult getResult() {
		return result;
	}
	
	public void setResult(AnalysisResult result) {
		this.result = result;
	}
	
	public MessageType getMessageType() {
		return MessageType.ListenerResult;
	}
}
