package de.fraunhofer.iem.secucheck.ftql.fluentInterface.io;

/**
 * Interface for Parameter
 */
public interface Parameter extends Output, Input {
    /**
     * Returns the Parameter id
     *
     * @return parameter id
     */
    int getParameterId();
}
