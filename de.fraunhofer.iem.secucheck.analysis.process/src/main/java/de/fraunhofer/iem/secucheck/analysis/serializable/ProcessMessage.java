package de.fraunhofer.iem.secucheck.analysis.serializable;

public class ProcessMessage {
	protected MessageType messageType;
	protected AnalysisMessage analysisMessage;
	
	public AnalysisMessage getAnalysisMessage() {
		return analysisMessage;
	}
	
	public MessageType getMessageType() {
		return messageType;
	}
}