package de.fraunhofer.iem.secucheck.analysis.serializable.result;

import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.AnalysisMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.MessageType;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessage;

public final class CompleteResult extends ProcessMessage implements AnalysisMessage {
	
	private final SecucheckTaintAnalysisResult result;
	
	public CompleteResult() {
		this.result = null;
	}
	
	public CompleteResult(SecucheckTaintAnalysisResult result) {
		super.messageType = getMessageType();
		this.result = result;
	}

	public MessageType getMessageType() {
		return MessageType.AnalysisResult;
	}
	
	public SecucheckTaintAnalysisResult getResult() {
		return result;
	}
}
