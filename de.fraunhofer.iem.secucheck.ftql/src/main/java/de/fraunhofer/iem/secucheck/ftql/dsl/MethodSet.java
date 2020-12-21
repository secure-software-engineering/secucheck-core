package de.fraunhofer.iem.secucheck.ftql.dsl;

import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.ftql.fluentInterface.methodpack.Method;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.taintflowpack.FlowParticipant;

public class MethodSet implements FlowParticipant {
    private final String methodSetName;
    private final List<Method> methods = new ArrayList<Method>();

    public MethodSet(String methodSetName) {
        this.methodSetName = methodSetName;
    }

    public MethodSet addMethod(Method method) {
        methods.add(method);
        return this;
    }

    public String getName() {
        return methodSetName;
    }

    public List<Method> getMethods() {
        return methods;
    }
}
