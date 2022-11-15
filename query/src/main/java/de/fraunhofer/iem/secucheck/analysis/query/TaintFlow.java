package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

/**
 * This class represents the TaintFlow
 */
public interface TaintFlow {
    /**
     * Returns the list of source methods
     *
     * @return List of source methods
     */
    public List<MethodImpl> getFrom();

    /**
     * Returns the list of sink methods
     *
     * @return List of sink methods
     */
    public List<MethodImpl> getTo();

    /**
     * Returns the list of required propagator methods
     *
     * @return List of required propagator methods
     */
    public List<MethodImpl> getNotThrough();

    /**
     * Returns the list of sanitizer methods
     *
     * @return List of sanitizer methods
     */
    public List<MethodImpl> getThrough();
}