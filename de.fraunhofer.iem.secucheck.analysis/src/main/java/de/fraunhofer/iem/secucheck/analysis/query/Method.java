package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

public interface Method {
	public List<Output> getOutputs();
	public List<Input> getInputs();
	public String getName();
	public String getSignature();
}
