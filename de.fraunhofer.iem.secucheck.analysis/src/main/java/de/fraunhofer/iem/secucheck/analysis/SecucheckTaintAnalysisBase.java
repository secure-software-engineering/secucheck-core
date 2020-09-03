package de.fraunhofer.iem.secucheck.analysis;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import boomerang.preanalysis.BoomerangPretransformer;
import de.fraunhofer.iem.secucheck.analysis.internal.CompositeTaintFlowAnalysis;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.query.OS;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.CompositeTaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;
import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Unit;
import soot.jimple.toolkits.ide.icfg.BiDiInterproceduralCFG;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.options.Options;
import test.core.selfrunning.ImprecisionException;

public abstract class SecucheckTaintAnalysisBase implements SecucheckAnalysis {

	protected final ReentrantLock lock;  
	
	protected long analysisTime;
	protected BiDiInterproceduralCFG<Unit, SootMethod> icfg;
	
	private OS os;
	private String appClassPath;
	private String sootClassPath;
	private List<EntryPoint> entryPoints;
	private List<CompositeTaintFlowQueryImpl> flowQueries;
	private AnalysisResultListener resultListener;
	private SecucheckTaintAnalysisResult result;
	
	public SecucheckTaintAnalysisBase() { 
		this.lock = new ReentrantLock();
	}
	
	public SecucheckTaintAnalysisBase(OS os, String appClassPath,
			String sootClassPath, List<EntryPoint> entryPoints,
			AnalysisResultListener resultListener) {
		this();
		this.os = os;
		this.appClassPath = appClassPath;
		this.sootClassPath = sootClassPath;
		this.entryPoints = entryPoints;
		this.resultListener = resultListener;
	}
	
	@Override
	public void setOs(OS os) {
		this.os = os;
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
	public SecucheckTaintAnalysisResult run(List<CompositeTaintFlowQueryImpl> flowQueries) 
			throws Exception  {		
		Utility.ValidateCompositeFlowQueries(flowQueries);
		lock.lock();
		try {
			this.flowQueries = flowQueries;
			this.result = new SecucheckTaintAnalysisResult();
			
			this.initializeSootWithEntryPoints(
					Utility.getCombinedSootClassPath(this.os, 
							this.appClassPath, this.sootClassPath),
					this.entryPoints);
			
			return this.analyze();
		} finally {
			lock.unlock();
		}
	}
	
	private void initializeSootWithEntryPoints(String sootClassPath, List<EntryPoint> entryPoints) 
			throws Exception {
		
		G.v().reset();

		Options.v().set_keep_line_number(true);

		Options.v().setPhaseOption("cg.cha", "on");
		Options.v().setPhaseOption("cg", "all-reachable:true");
		Options.v().set_output_format(Options.output_format_none);

		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().setPhaseOption("jb", "use-original-names:true");

		Options.v().set_exclude(excludedPackages());
		Options.v().set_soot_classpath(sootClassPath);
		Options.v().set_prepend_classpath(true);
		Options.v().set_whole_program(true);

		Scene.v().addBasicClass("java.lang.StringBuilder", SootClass.BODIES);
		Scene.v().addBasicClass("java.lang.System", SootClass.BODIES);
		Scene.v().addBasicClass("java.lang.ThreadGroup", SootClass.BODIES);
		Scene.v().addBasicClass("java.lang.ClassLoader", SootClass.BODIES);
		Scene.v().addBasicClass("java.security.PrivilegedActionException", SootClass.BODIES);
		Scene.v().addBasicClass("java.lang.Thread", SootClass.BODIES);
		Scene.v().addBasicClass("java.lang.AbstractStringBuilder", SootClass.BODIES);

		Runnable runnable = () -> {
			List<SootMethod> entries = new ArrayList<SootMethod>();
			for (EntryPoint entry : entryPoints) {
				SootClass sootClass = Scene.v().forceResolve(entry.getCanonicalClassName(),
						SootClass.BODIES);
				sootClass.setApplicationClass();
				if (entry.isAllMethods()) {
					entries.addAll(sootClass.getMethods());
				} else {
					entry.getMethods().forEach(y -> 
						entries.add(sootClass.getMethodByName(y)));
				}
			}
			Scene.v().setEntryPoints(entries);
		};
		
		Utility.executeSootRunnable(runnable, "Could not find entry point.");
		
		Scene.v().forceResolve("java.lang.Thread", SootClass.BODIES).setApplicationClass();
		Scene.v().loadNecessaryClasses();
	}

	
	protected boolean includeJDK() {
		return true;
	}

	protected List<String> excludedPackages() {
		List<String> excludedPackages = new LinkedList<>();
		excludedPackages.add("sun.*");
		excludedPackages.add("javax.*");
		excludedPackages.add("com.sun.*");
		excludedPackages.add("com.ibm.*");
		excludedPackages.add("org.xml.*");
		excludedPackages.add("org.w3c.*");
		excludedPackages.add("apple.awt.*");
		excludedPackages.add("com.apple.*");
		return excludedPackages;
	}

	private SecucheckTaintAnalysisResult analyze() {
		Transform transform = new Transform("wjtp.ifds", createAnalysisTransformer());
		PackManager.v().getPack("wjtp").add(transform);
		PackManager.v().getPack("cg").apply();
		PackManager.v().getPack("wjtp").apply();
		if (resultListener != null) {
			resultListener.reportCompleteResult(this.result);
		}
		return this.result;
	}
	
	private SceneTransformer createAnalysisTransformer() throws ImprecisionException {
		return new SceneTransformer() {
			protected void internalTransform(String phaseName, Map options) {
				BoomerangPretransformer.v().apply();
				icfg = new JimpleBasedInterproceduralCFG(true);
				try {
					executeAnalysis();
				} catch (Exception e) {	}
			}
		};
	}

	private void executeAnalysis() throws Exception {
		for (CompositeTaintFlowQueryImpl flowQuery : this.flowQueries) {
			if (resultListener != null && resultListener.isCancelled()) {
				break;
			}
			Analysis analysis = new CompositeTaintFlowAnalysis(icfg, flowQuery, resultListener);
			CompositeTaintFlowQueryResult singleResult = (CompositeTaintFlowQueryResult) analysis.run();
			this.result.addResult(flowQuery, singleResult);
			if (resultListener != null) {
				resultListener.reportCompositeFlowResult((CompositeTaintFlowQueryResult) singleResult);
			}
		}
	}

}
