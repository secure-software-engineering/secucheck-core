package de.fraunhofer.iem.secucheck.ftql.dsl;

import de.fraunhofer.iem.secucheck.ftql.fluentInterface.methodpack.Method;

public class MethodWithInAndOutThisObjReturnParam {
    private final MethodImpl method;
    private OutputDeclarationImpl outputDeclaration;

    public MethodWithInAndOutThisObjReturnParam(OutputDeclarationImpl outputDeclaration, MethodImpl method) {
        this.method = method;
        this.outputDeclaration = outputDeclaration;
        method.setOutputDeclaration(this.outputDeclaration);
    }

    public MethodWithInAndOutThisObjReturnParam param(int parameterID) {
        outputDeclaration.addOutput(new ParameterImpl(parameterID));
        return this;
    }

    public Method configure() {
        method.setOutputDeclaration(outputDeclaration);
        return method;
    }
}
