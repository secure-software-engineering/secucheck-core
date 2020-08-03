package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

public final class MethodImpl implements Method {

	private String name;
	private String signature;
	private List<InputParameter> inputParameters;
	private List<OutputParameter> outputParameters;
	private ReturnValue returnValue;
	 
	public MethodImpl() { }
	
	@Override public List<OutputParameter> getOutputParameters() { return this.outputParameters; }
	@Override public List<InputParameter> getInputParameters() { return this.inputParameters; }
	@Override public String getName() { return this.name; }
	@Override public String getSignature() { return this.signature; }
	@Override public ReturnValue getReturnValue() { return this.returnValue; }
	
	public void setOutputParameters(List<OutputParameter> outputs) { this.outputParameters = outputs; }
	public void setInputParameters(List<InputParameter> inputs) {	this.inputParameters = inputs; }
	public void setName(String name) { this.name = name; }
	public void setSignature(String signature) { this.signature = signature; }
	public void setReturnValue(ReturnValue returnValue) { this.returnValue = returnValue; }

}
