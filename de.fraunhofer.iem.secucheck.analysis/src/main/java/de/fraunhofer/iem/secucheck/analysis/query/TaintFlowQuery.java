package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.datastructures.Copyable;

public interface TaintFlowQuery {
	public List<Method> getFrom();
	public List<Method> getTo();
	public List<Method> getNotThrough();
	public List<Method> getThrough();
}
