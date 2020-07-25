package de.fraunhofer.iem.secucheck.analysis.serializable;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import de.fraunhofer.iem.secucheck.analysis.serializable.query.CompleteQuery;
import de.fraunhofer.iem.secucheck.analysis.serializable.result.CompleteResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.result.ListenerResult;

public final class MessageSerializer extends StdDeserializer<ProcessMessage>{
	
	public MessageSerializer() { this(null); }
	public MessageSerializer(final Class<?> vc) { super(vc); }
	
	@Override
	public ProcessMessage deserialize(final JsonParser jsonParser,
            final DeserializationContext deserializationContext) 
            		throws IOException {
		final JsonNode node = jsonParser.getCodec().readTree(jsonParser);
        final ObjectMapper mapper = (ObjectMapper) jsonParser.getCodec();
        ProcessMessage message = new ProcessMessage();
    	message.messageType = mapper.convertValue(
    			node.get("messageType"), MessageType.class);
    	switch (message.messageType) {
			case AnalysisResult:
				message.analysisMessage = mapper.convertValue(
	        			node.get("analysisMessage"), CompleteResult.class);
				break;
			case CompleteQuery:
				message.analysisMessage = mapper.convertValue(
	        			node.get("analysisMessage"), CompleteQuery.class);
				break;
			case ListenerResult:
				message.analysisMessage = mapper.convertValue(
	        			node.get("analysisMessage"), ListenerResult.class);
				break;
    	}
        return message;
	}
}