package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.datastructures.Copyable;

public interface TaintFlowQuery {
	public List<MethodImpl> getFrom();
	public List<MethodImpl> getTo();
	public List<MethodImpl> getNotThrough();
	public List<MethodImpl> getThrough();
}