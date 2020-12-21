package de.fraunhofer.iem.secucheck.ftql.fluentInterface.methodpack;

import de.fraunhofer.iem.secucheck.ftql.dsl.MethodSet;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.io.InputDeclaration;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.io.OutputDeclaration;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.taintflowpack.FlowParticipant;

/**
 * Interface for Method
 */
public interface Method extends FlowParticipant {

    /**
     * Returns the Method signature
     *
     * @return Method signature
     */
    String getSignature();

    /**
     * Returns the MethodSet
     *
     * @return MethodSet
     */
    MethodSet getMethodSet();

    /**
     * Returns the InputDeclaration
     *
     * @return InputDeclaration
     */
    InputDeclaration getInputDeclaration();

    /**
     * Returns the OutputDeclaration
     *
     * @return OutputDeclaration
     */
    OutputDeclaration getOutputDeclaration();
}
