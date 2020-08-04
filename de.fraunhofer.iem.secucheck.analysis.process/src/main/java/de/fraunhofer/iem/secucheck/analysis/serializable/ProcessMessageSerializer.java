package de.fraunhofer.iem.secucheck.analysis.serializable;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessage;

public class ProcessMessageSerializer {
	
	private static ObjectMapper objectMapper = new ObjectMapper();
	
	static {
	    final SimpleModule module = new SimpleModule();
	    objectMapper = new ObjectMapper();
	    objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
	    objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
	    
	    module.addDeserializer(ProcessMessage.class, new MessageDeserializer());
	    
	    module.addKeyDeserializer(CompositeTaintFlowQuery.class,
	    		new SimpleKeyDeserializer<CompositeTaintFlowQuery>(objectMapper,
	    				CompositeTaintFlowQuery.class));
	    
	    module.addKeyDeserializer(CompositeTaintFlowQueryImpl.class,
	    		new SimpleKeyDeserializer<CompositeTaintFlowQueryImpl>(objectMapper,
	    				CompositeTaintFlowQueryImpl.class));
	    
	    module.addKeyDeserializer(TaintFlowQuery.class,
	    		new SimpleKeyDeserializer<TaintFlowQuery>(objectMapper,
	    				TaintFlowQuery.class));
	    
	    module.addKeyDeserializer(TaintFlowQueryImpl.class,
	    		new SimpleKeyDeserializer<TaintFlowQueryImpl>(objectMapper,
	    				TaintFlowQueryImpl.class));    

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



























