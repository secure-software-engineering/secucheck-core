package de.fraunhofer.iem.secucheck.analysis.serializable.query;

import de.fraunhofer.iem.secucheck.analysis.serializable.AnalysisMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.MessageType;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessage;

public class CancellationMessage extends ProcessMessage implements AnalysisMessage {
	public CancellationMessage() {
		super.messageType = MessageType.Cancellation;
	}
}
