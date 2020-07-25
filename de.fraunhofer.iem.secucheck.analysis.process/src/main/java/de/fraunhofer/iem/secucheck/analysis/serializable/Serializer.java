package de.fraunhofer.iem.secucheck.analysis.serializable;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

import de.fraunhofer.iem.secucheck.analysis.serializable.MessageSerializer;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessage;
public class Serializer {
	
	private static ObjectMapper objectMapper = new ObjectMapper();
	
	static {
	    final SimpleModule module = new SimpleModule();
	    objectMapper = new ObjectMapper();
	    module.addDeserializer(ProcessMessage.class, new MessageSerializer());
	    objectMapper.registerModule(module);
	}
	
	public static String serializeToJsonString(ProcessMessage message) 
			throws JsonProcessingException {
		return objectMapper.writeValueAsString(message);
	}
	
	public static ProcessMessage deserializeFromJsonString(String string) 
			throws JsonParseException, JsonMappingException, IOException {
		return objectMapper.readValue(string, ProcessMessage.class);
	}
	
}



























