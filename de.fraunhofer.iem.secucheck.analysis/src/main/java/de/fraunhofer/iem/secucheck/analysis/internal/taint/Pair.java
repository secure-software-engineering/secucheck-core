package de.fraunhofer.iem.secucheck.analysis.internal.taint;

public interface Pair<T> {
	public T getFirst();
	public T getSecond();
	public void setFirst(T first);
	public void setSecond(T second);
}
