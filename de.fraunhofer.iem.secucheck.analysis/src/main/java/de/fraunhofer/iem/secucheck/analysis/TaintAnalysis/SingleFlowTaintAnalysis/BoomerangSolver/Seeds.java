package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver;

import java.util.Set;

import boomerang.BackwardQuery;
import boomerang.ForwardQuery;

class Seeds {
	
	public Set<ForwardQuery> sources;
	public Set<BackwardQuery> sinks;
	
	public Seeds(Set<ForwardQuery> sources, Set<BackwardQuery> sinks) {
		this.sources = sources;
		this.sinks = sinks;
	}
	
	public void setSources(Set<ForwardQuery> sources) { this.sources = sources; }
	public void setSinks(Set<BackwardQuery> sinks) { this.sinks = sinks; }		
	public Set<ForwardQuery> getSources() { return sources; }
	public Set<BackwardQuery> getSinks() { return sinks; }		
}
