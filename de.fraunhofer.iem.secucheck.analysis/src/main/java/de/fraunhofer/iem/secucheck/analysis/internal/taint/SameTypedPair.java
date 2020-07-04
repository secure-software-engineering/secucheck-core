package de.fraunhofer.iem.secucheck.analysis.internal.taint;

public class SameTypedPair<T> implements Pair<T> {
	
	private T first;
	private T second;
	
	public SameTypedPair(T first, T second) {
		this.first = first;
		this.second = second;
	}
	
	public T getFirst() { return first; }
	public T getSecond() { return second; }
	public void setFirst(T first) { this.first = first; }
	public void setSecond(T second) { this.second = second; }
}