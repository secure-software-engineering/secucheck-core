package de.fraunhofer.iem.secucheck.ftql.dsl;

import de.fraunhofer.iem.secucheck.ftql.fluentInterface.io.InputDeclaration;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.io.OutputDeclaration;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.methodpack.Method;

class MethodImpl implements Method {
    private String methodSignature;
    private MethodSet methodSet;
    private InputDeclaration inputDeclaration = null;
    private OutputDeclaration outputDeclaration = null;

    public String getSignature() {
        return methodSignature;
    }

    public void setSignature(String methodSignature) {
        this.methodSignature = methodSignature;
    }

    public MethodSet getMethodSet() {
        return methodSet;
    }

    public void setMethodSet(MethodSet methodSet) {
        this.methodSet = methodSet;
    }

    public InputDeclaration getInputDeclaration() {
        return inputDeclaration;
    }

    public void setInputDeclaration(InputDeclaration inputDeclaration) {
        this.inputDeclaration = inputDeclaration;
    }

    public OutputDeclaration getOutputDeclaration() {
        return outputDeclaration;
    }

    public void setOutputDeclaration(OutputDeclaration outputDeclaration) {
        this.outputDeclaration = outputDeclaration;
    }

    public MethodImpl(String methodSignature) {
        this.methodSignature = methodSignature;
    }
}
