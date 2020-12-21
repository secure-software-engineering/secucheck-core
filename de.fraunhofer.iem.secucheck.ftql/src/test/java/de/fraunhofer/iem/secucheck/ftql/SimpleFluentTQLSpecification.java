package de.fraunhofer.iem.secucheck.ftql;

import de.fraunhofer.iem.secucheck.ftql.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.ftql.dsl.MethodSet;
import de.fraunhofer.iem.secucheck.ftql.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.ftql.dsl.constants.LOCATION;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.methodpack.Method;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.spec.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

public class SimpleFluentTQLSpecification implements FluentTQLUserInterface {
    static Method source = new MethodConfigurator("Test: java.lang.String getSecret()")
            .out().returnValue()
            .configure();

    static Method sanitizer = new MethodConfigurator("Test: java.lang.String sanitize(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    static Method sink = new MethodConfigurator("Test: void printSecret(java.lang.String)")
            .in().param(0)
            .configure();

    static MethodSet myMethodSet = new MethodSet("Testing MethodSet")
            .addMethod(source)
            .addMethod(sanitizer)
            .addMethod(sink);

    @Override
    public List<FluentTQLSpecification> getFluentTQLSpecification() {

        TaintFlowQuery simpleTaintFlow = new TaintFlowQueryBuilder()
                .from(source)
                .notThrough(sanitizer)
                .to(sink)
                .report("A simple TaintFlow is present here!!!")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecification = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecification.add(simpleTaintFlow);

        return myFluentTQLSpecification;
    }
}
