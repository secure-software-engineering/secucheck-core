package de.fraunhofer.iem.secucheck.analysis.datastructures;

/**
 * This is the Pair type with two elements are of same type.
 *
 * @param <T> First Type
 * @author Tareen, Abdul Rehman
 */
public class SameTypedPair<T> implements Pair<T, T> {

    private T first;
    private T second;

    public SameTypedPair() {
    }

    public SameTypedPair(T first, T second) {
        this.first = first;
        this.second = second;
    }

    @Override
    public T getFirst() {
        return first;
    }

    @Override
    public T getSecond() {
        return second;
    }

    @Override
    public void setFirst(T first) {
        this.first = first;
    }

    @Override
    public void setSecond(T second) {
        this.second = second;
    }
}