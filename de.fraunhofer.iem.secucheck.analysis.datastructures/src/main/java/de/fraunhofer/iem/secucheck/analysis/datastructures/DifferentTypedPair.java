package de.fraunhofer.iem.secucheck.analysis.datastructures;

/**
 * This is the Pair type with two elements are of different type.
 *
 * @param <T> First Type
 * @param <V> Second Type
 * @author Tareen, Abdul Rehman
 */
public class DifferentTypedPair<T, V> implements Pair<T, V> {

    private T first;
    private V second;

    public DifferentTypedPair() {
    }

    public DifferentTypedPair(T first, V second) {
        this.first = first;
        this.second = second;
    }

    @Override
    public T getFirst() {
        return first;
    }

    @Override
    public V getSecond() {
        return second;
    }

    @Override
    public void setFirst(T first) {
        this.first = first;
    }

    @Override
    public void setSecond(V second) {
        this.second = second;
    }
}
