package de.fraunhofer.iem.secucheck.analysis.serializable;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import de.fraunhofer.iem.secucheck.analysis.serializable.query.CancellationMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.query.CompleteQuery;
import de.fraunhofer.iem.secucheck.analysis.serializable.result.CompleteResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.result.ListenerResult;

@SuppressWarnings("serial")
public final class MessageDeserializer extends StdDeserializer<ProcessMessage> {
	public MessageDeserializer() { this(null); }
	public MessageDeserializer(final Class<?> vc) { super(vc); }
	
	@Override
	public ProcessMessage deserialize(final JsonParser jsonParser,
            final DeserializationContext deserializationContext) throws IOException {
		final JsonNode node = jsonParser.getCodec().readTree(jsonParser);
        final ObjectMapper mapper = (ObjectMapper) jsonParser.getCodec();
        ProcessMessage message = new ProcessMessage();
    	message.messageType = mapper.convertValue(node.get("messageType"), MessageType.class);
    	switch (message.messageType) {
			case AnalysisResult: return mapper.convertValue(node, CompleteResult.class);
			case CompleteQuery: return mapper.convertValue(node, CompleteQuery.class);
			case ListenerResult: return mapper.convertValue(node, ListenerResult.class);
			case Cancellation: return mapper.convertValue(node, CancellationMessage.class);
    	}
        return message;
	}
}