package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

/**
 * Implementation of Method
 */
public final class MethodImpl implements Method {

    private boolean isOutputThis;
    private boolean isInputThis;

    private String name;
    private String signature;

    private List<InputParameter> inputParameters;
    private List<OutputParameter> outputParameters;

    private ReturnValue returnValue;

    public MethodImpl() {
    }

    @Override
    public boolean isOutputThis() {
        return this.isOutputThis;
    }

    @Override
    public boolean isInputThis() {
        return this.isInputThis;
    }

    @Override
    public List<OutputParameter> getOutputParameters() {
        return this.outputParameters;
    }

    @Override
    public List<InputParameter> getInputParameters() {
        return this.inputParameters;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getSignature() {
        return this.signature;
    }

    @Override
    public ReturnValue getReturnValue() {
        return this.returnValue;
    }

    public void setOutputThis(boolean value) {
        this.isOutputThis = value;
    }

    public void setInputThis(boolean value) {
        this.isInputThis = value;
    }

    public void setOutputParameters(List<OutputParameter> outputs) {
        this.outputParameters = outputs;
    }

    public void setInputParameters(List<InputParameter> inputs) {
        this.inputParameters = inputs;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public void setReturnValue(ReturnValue returnValue) {
        this.returnValue = returnValue;
    }
}
