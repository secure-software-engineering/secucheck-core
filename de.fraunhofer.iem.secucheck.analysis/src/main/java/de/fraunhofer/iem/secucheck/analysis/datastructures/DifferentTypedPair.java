package de.fraunhofer.iem.secucheck.analysis.datastructures;

public class DifferentTypedPair<T, V> implements Pair<T, V> {

	private T first;
	private V second;
	
	public DifferentTypedPair(T first, V second) {
		this.first = first;
		this.second = second;
	}
	
	@Override
	public T getFirst() { return first; }
	@Override
	public V getSecond() { return second; }
	@Override
	public void setFirst(T first) { this.first = first; }
	@Override
	public void setSecond(V second) { this.second = second; }
}
