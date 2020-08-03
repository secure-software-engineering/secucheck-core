package de.fraunhofer.iem.secucheck.analysis.serializable;

import java.io.IOException;

import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.KeyDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class SimpleKeyDeserializer<T> extends KeyDeserializer {
	private final ObjectMapper mapper;
	private final Class<T> clazz;
	public SimpleKeyDeserializer(ObjectMapper mapper, Class<T> clazz) {
		this.mapper = mapper;
		this.clazz = clazz;
	}
	
	@Override
	public Object deserializeKey(String key, DeserializationContext ctxt)
			throws IOException {		
		return mapper.readValue(key, clazz);
	}
}
