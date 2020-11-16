package de.fraunhofer.iem.secucheck.analysis.internal;

import boomerang.Boomerang;
import boomerang.callgraph.ObservableICFG;
import boomerang.seedfactory.SeedFactory;
import soot.SootMethod;
import soot.Unit;
import wpds.impl.Weight.NoWeight;

public class SingleFlowBoomerang extends Boomerang { 
	
	private final SeedFactory<NoWeight> seedFactory;
	private final ObservableICFG<Unit, SootMethod> icfg;
	
	public SingleFlowBoomerang(SeedFactory<NoWeight> seedFactory, 
			ObservableICFG<Unit, SootMethod> icfg, TaintAnalysisOptions options){
		super(options);
		this.seedFactory = seedFactory;
		this.icfg = icfg;
	}
	
	@Override
	public ObservableICFG<Unit, SootMethod> icfg() {
		return this.icfg;
	}
	
	@Override
	public SeedFactory<NoWeight> getSeedFactory() {
		return this.seedFactory;
	}
}
