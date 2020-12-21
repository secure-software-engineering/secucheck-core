package de.fraunhofer.iem.secucheck.analysis.evaluation;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.OS;
import de.fraunhofer.iem.secucheck.analysis.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.SecucheckAnalysisDefaultConfiguration;
import de.fraunhofer.iem.secucheck.analysis.SecucheckTaintAnalysis;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;

import de.fraunhofer.iem.secucheck.analysis.query.Solver;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.CompositeTaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.ftql.reader.FtqlReader;

public class Main {
	
	public static void main(String[] args) {
		
		try {	
			SecucheckTaintAnalysis secucheckAnalysis = new SecucheckTaintAnalysis();
			SecucheckAnalysisConfiguration configuration = getAnalysisConfiguration(Solver.BOOMERANG3, OS.LINUX);		
			secucheckAnalysis.setConfiguration(configuration);
			List<CompositeTaintFlowQueryImpl> compositeQueries = FtqlReader.getSecucheckCoreQueries(getSpecsClassPath());
			SecucheckTaintAnalysisResult result = secucheckAnalysis.run(compositeQueries);
			System.out.println();
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
	private static String getAppClassPath() {
		return System.getProperty("user.dir") + File.separator + "target" + File.separator + "classes";
	}
	
	private static String getSootClassPath() {		
		return 	System.getProperty("java.home") + File.separator + "lib" + File.separator +"rt.jar" ;	
	}
	
	private static String getSpecsClassPath() {		
		return 	System.getProperty("java.home") + File.separator + "lib" + File.separator +"rt.jar" ;	
	}
	
	private static List<EntryPoint> getEntryPoints(){
		List<EntryPoint> entryPoints = new ArrayList<EntryPoint>();
	
		EntryPoint entryPoint = new EntryPoint();
		entryPoint.setCanonicalClassName("AnalyzeMeLevel1");
		entryPoint.setAllMethods(true);
		entryPoints.add(entryPoint);
		
		entryPoint = new EntryPoint();
		entryPoint.setCanonicalClassName("AnalyzeMeLevel2");
		entryPoint.setAllMethods(true);
		entryPoints.add(entryPoint);
		
		return entryPoints;
	}
	
	private static AnalysisResultListener getConsoleResultListener() {
		return new AnalysisResultListener() {
			
			@Override
			public void reportFlowResult(TaintFlowQueryResult result) {
				System.out.println();
				System.out.println("Recieved single flow result, size:" + result.size());
			}
			
			@Override
			public void reportCompositeFlowResult(CompositeTaintFlowQueryResult result) {
				System.out.println();
				System.out.println("Recieved composite flow result, size:" + result.size());
			}
			
			@Override
			public void reportCompleteResult(SecucheckTaintAnalysisResult result) {
				System.out.println();
				System.out.println("Recieved complete result, size:" + result.size());
			}
			
			@Override
			public boolean isCancelled() {
				return false;
			}
		};
	}
	
	private static SecucheckAnalysisConfiguration getAnalysisConfiguration(Solver solver, OS os) {
		AnalysisResultListener resultListener = getConsoleResultListener();
		SecucheckAnalysisConfiguration configuration = new SecucheckAnalysisDefaultConfiguration();
		configuration.setOs(os);
		configuration.setSolver(solver);
		configuration.setAnalysisEntryPoints(getEntryPoints());
		configuration.setApplicationClassPath(getAppClassPath());
		configuration.setSootClassPathJars(getSootClassPath());
		configuration.setListener(resultListener);
		return configuration;
	}
}
