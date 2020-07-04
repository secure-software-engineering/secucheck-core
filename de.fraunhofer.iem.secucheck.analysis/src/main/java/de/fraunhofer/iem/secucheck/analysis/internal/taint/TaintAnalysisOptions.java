package de.fraunhofer.iem.secucheck.analysis.internal.taint;

import boomerang.DefaultBoomerangOptions;

public class TaintAnalysisOptions extends DefaultBoomerangOptions {
	@Override
	public boolean trackStrings() {
		return true;
	}
	
	@Override
	public boolean arrayFlows() {
		return true;
	}
}
