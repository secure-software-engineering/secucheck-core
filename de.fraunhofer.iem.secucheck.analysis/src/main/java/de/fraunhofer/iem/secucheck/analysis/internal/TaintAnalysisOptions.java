package de.fraunhofer.iem.secucheck.analysis.internal;

import boomerang.DefaultBoomerangOptions;

class TaintAnalysisOptions extends DefaultBoomerangOptions {
	
	@Override
	public boolean trackStrings() {
		return true;
	}
	
	@Override
	public boolean allowMultipleQueries() {
		return true;
	}
}
