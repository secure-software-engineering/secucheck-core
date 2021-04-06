package de.fraunhofer.iem.secucheck.analysis.datastructures;

/**
 * Interface for creating a generic Pair type.
 *
 * @param <T> First element type
 * @param <V> Second element type
 * @author Tareen, Abdul Rehman
 */
public interface Pair<T, V> {
    /**
     * returns the first element of the pair
     *
     * @return First element
     */
    public T getFirst();

    /**
     * returns the second element of the pair
     *
     * @return Second element
     */
    public V getSecond();

    /**
     * Setter for first element
     *
     * @param first First element
     */
    public void setFirst(T first);

    /**
     * Setter for second element
     *
     * @param second Second element
     */
    public void setSecond(V second);
}
