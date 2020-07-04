package de.fraunhofer.iem.secucheck.analysis;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import boomerang.preanalysis.BoomerangPretransformer;
import de.fraunhofer.iem.secucheck.analysis.internal.taint.TaintAnalysis;
import de.fraunhofer.iem.secucheck.custom.ProgressReporter;
import de.fraunhofer.iem.secucheck.marker.AnalysisResult;
import de.fraunhofer.iem.secucheck.marker.MarkerFactory;
import de.fraunhofer.iem.secucheck.query.Flow;
import de.fraunhofer.iem.secucheck.query.TaintFlow;
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

public class SpottyTestingFramework {

	protected BiDiInterproceduralCFG<Unit, SootMethod> icfg;
//	private HashSet<Assertion> expectedResults;
	protected long analysisTime;
	private List<TaintFlow> flowQueries;
	private ProgressReporter progressReporter;
	private AnalysisResult result;

	public SpottyTestingFramework(List<TaintFlow> flowQueries, List<Flow> flows, ProgressReporter progressReporter) {
		this.flowQueries = flowQueries;
		this.progressReporter = progressReporter;
	}

	protected SceneTransformer createAnalysisTransformer() throws ImprecisionException {
		return new SceneTransformer() {

			protected void internalTransform(String phaseName, @SuppressWarnings("rawtypes") Map options) {
				BoomerangPretransformer.v().apply();
				icfg = new JimpleBasedInterproceduralCFG(true);
				executeAnalysis();
			}
		};
	}

	protected void executeAnalysis() {
		for (TaintFlow taintFlow : flowQueries) {
			new TaintAnalysis(icfg, taintFlow, result).run();
		}
	}

	public static AnalysisResult run(String sootClassPath, List<String> canonicalClassNames,
			List<TaintFlow> flowQueries, List<Flow> flows, ProgressReporter progressReporter)
			throws ImprecisionException {
		SpottyTestingFramework s = new SpottyTestingFramework(flowQueries, flows, progressReporter);
		s.initializeSootWithEntryPoint(sootClassPath, canonicalClassNames);
		return s.analyze();
	}

	private AnalysisResult analyze() {
		this.result = MarkerFactory.eINSTANCE.createAnalysisResult();
		try {
			Transform transform = new Transform("wjtp.ifds", createAnalysisTransformer());
			PackManager.v().getPack("wjtp").add(transform);
			PackManager.v().getPack("cg").apply();
			PackManager.v().getPack("wjtp").apply();

			return this.result;
		} finally {
			this.result = null;
		}
	}

	@SuppressWarnings("static-access")
	private void initializeSootWithEntryPoint(String sootClassPath, List<String> entryPoints) {
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

		try {
			for (String entry : entryPoints) {
				SootClass sootTestClass = Scene.v().forceResolve(entry, SootClass.BODIES);
				sootTestClass.setApplicationClass();
			}
		} catch (Error | Exception e) {
			// Normally the "Error" class indicates problems that are outside of application
			// scope to deal with (OutOfMemoryError etc).
			// But soot throws instances of class "Error" in case of problems. So we are
			// forced to catch it here.
			throw new RuntimeException("Could not find entry point.");
		}
		Scene.v().forceResolve("java.lang.Thread", SootClass.BODIES).setApplicationClass();
		Scene.v().loadNecessaryClasses();

	}

	protected boolean includeJDK() {
		return true;
	}

	public List<String> excludedPackages() {
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

}
