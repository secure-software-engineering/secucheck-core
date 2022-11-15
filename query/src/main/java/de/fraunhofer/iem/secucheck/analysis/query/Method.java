package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

/**
 * This represents the Method
 */
public interface Method {
    /**
     * Returns true if there is a out flow this-object
     *
     * @return Boolean
     */
    boolean isOutputThis();

    /**
     * Returns true if there is a in flow this-object
     *
     * @return Boolean
     */
    boolean isInputThis();

    String getName();

    /**
     * Return method signature
     *
     * @return Method signature
     */
    String getSignature();

    /**
     * Returns list of Outflow parameters
     *
     * @return List of outflow parameters
     */
    List<OutputParameter> getOutputParameters();

    /**
     * Returns list Inflow parameters
     *
     * @return List of inflow parameters
     */
    List<InputParameter> getInputParameters();

    /**
     * Returns true if there is a Outflow return value
     *
     * @return Boolean
     */
    ReturnValue getReturnValue();
}
