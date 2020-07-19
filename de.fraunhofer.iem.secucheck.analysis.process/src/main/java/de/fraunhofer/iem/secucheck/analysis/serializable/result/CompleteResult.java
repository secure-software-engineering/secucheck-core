package de.fraunhofer.iem.secucheck.analysis.serializable.result;

import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.AnalysisMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.MessageType;

public final class CompleteResult implements AnalysisMessage {
	
	private final SecucheckTaintAnalysisResult result;
	
	public CompleteResult(SecucheckTaintAnalysisResult result) {
		this.result = result;
	}

	public MessageType getMessageType() {
		return MessageType.AnalysisResult;
	}

}
