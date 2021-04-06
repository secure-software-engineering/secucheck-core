package de.fraunhofer.iem.secucheck.analysis.datastructures;

/**
 * Interface for Copyable objects to another object.
 *
 * @param <T> Type
 * @author Tareen, Abdul Rehman
 */
public interface Copyable<T> {
    /**
     * Copy this-object to given object
     *
     * @param copy Object
     */
    public void copyTo(T copy);
}
