package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

public interface Method {
	String getName();
	String getSignature();
	List<OutputParameter> getOutputParameters();
	List<InputParameter> getInputParameters();
	ReturnValue getReturnValue();
}
