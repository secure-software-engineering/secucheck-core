package de.fraunhofer.iem.secucheck.analysis;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.query.OS;
import de.fraunhofer.iem.secucheck.analysis.query.Solver;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.AnalysisResultListener;

/**
 * Default implementation of Secucheck Analysis configurations
 */
public class SecucheckAnalysisDefaultConfiguration implements SecucheckAnalysisConfiguration{
	
	private OS os;
	private Solver solver;
	private String appClassPath;
	private String sootClassPath;
	private List<EntryPoint> entryPoints;
	private AnalysisResultListener resultListener;
	
	@Override
	public void setOs(OS os) {
		this.os = os;
	}
	
	@Override
	public void setSolver(Solver solver) {
		this.solver = solver;
	}
	
	@Override
	public void setApplicationClassPath(String appClassPath) {
		this.appClassPath = appClassPath;
	}

	@Override
	public void setSootClassPathJars(String sootClassPath) {
		this.sootClassPath = sootClassPath;
	}	
	
	@Override
	public void setAnalysisEntryPoints(List<EntryPoint> entryPoints) {
		this.entryPoints = entryPoints;
	}
	
	@Override
	public void setListener(AnalysisResultListener resultListener) {
		this.resultListener = resultListener;
	}

	@Override
	public OS getOs() {
		return this.os;
	}
	
	@Override
	public Solver getSolver() {
		return this.solver;
	}

	@Override
	public String getSootClassPathJars() {
		return this.sootClassPath;
	}

	@Override
	public String getApplicationClassPath() {
		return this.appClassPath;
	}

	@Override
	public List<EntryPoint> getAnalysisEntryPoints() {
		return this.entryPoints;
	}

	@Override
	public AnalysisResultListener getListener() {
		return this.resultListener;
	}
}
