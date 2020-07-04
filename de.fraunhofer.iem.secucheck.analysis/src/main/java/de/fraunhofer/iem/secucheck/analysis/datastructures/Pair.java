package de.fraunhofer.iem.secucheck.analysis.datastructures;

public interface Pair<T,V> {
	public T getFirst();
	public V getSecond();
	public void setFirst(T first);
	public void setSecond(V second);
}
