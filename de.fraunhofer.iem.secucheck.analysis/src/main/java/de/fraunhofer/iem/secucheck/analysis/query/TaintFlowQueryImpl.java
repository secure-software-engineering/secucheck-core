package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.ArrayList;
import java.util.List;

import boomerang.seedfactory.Method;

public final class TaintFlowQueryImpl implements TaintFlowQuery {

	private final List<Method> froms;
	private final List<Method> tos;
	private final List<Method> notThroughs;
	private final List<Method> throughs;
	
	public TaintFlowQueryImpl() {
		this.froms = new ArrayList<Method>();
		this.tos = new ArrayList<Method>();
		this.notThroughs = new ArrayList<Method>();
		this.throughs = new ArrayList<Method>();
	}
	
	@Override public List<Method> getFrom() { return this.froms; }
	@Override public List<Method> getTo() { return this.tos; }
	@Override public List<Method> getNotThrough() { return this.notThroughs; }
	@Override public List<Method> getThrough() { return this.throughs;}
	
	public void addFrom(Method from) { this.froms.add(from); }
	public void addTo(Method to) { this.tos.add(to);}
	public void addNotThrough(Method through) { this.notThroughs.add(through);}
	public void addThrough(Method notThrough) { this.throughs.add(notThrough);}
}
