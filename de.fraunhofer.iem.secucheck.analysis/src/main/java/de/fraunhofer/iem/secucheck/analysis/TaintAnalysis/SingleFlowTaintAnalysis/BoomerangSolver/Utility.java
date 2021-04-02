package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver;


import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import boomerang.scene.WrappedClass;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.OS;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import soot.G;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.util.dot.DotGraph;

public class Utility {

	public static void initializeSootWithEntryPoints(String sootClassPath, List<EntryPoint> entryPoints)
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
		
		executeSootRunnable(runnable, "Could not find entry point.");
		
		Scene.v().forceResolve("java.lang.Thread", SootClass.BODIES).setApplicationClass();
		Scene.v().loadNecessaryClasses();
	}

	private static boolean includeJDK() {
		return true;
	}

	public static List<String> excludedPackages() {
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
	
	private static void drawCallGraph(CallGraph callGraph){
        DotGraph dot = new DotGraph("callgraph");
        Iterator<Edge> iteratorEdges = callGraph.iterator();

        System.out.println("Call Graph size : "+ callGraph.size());
        while (iteratorEdges.hasNext()) {
            Edge edge = iteratorEdges.next();
            String node_src = edge.getSrc().toString();
            String node_tgt = edge.getTgt().toString();
            dot.drawEdge(node_src, node_tgt);
        }
        dot.plot("<file-path>");
    }

	private static void executeSootRunnable(Runnable runable, String message) throws Exception {
		try {
			runable.run();
		} catch (Error | Exception e) {
			// Normally the "Error" class indicates problems that are outside of application
			// scope to deal with (OutOfMemoryError etc).
			// Soot throws instances of class "Error" in case of problems. So we are
			// forced to catch it here.
			throw new Exception(message, e);
		}
	}

	public static String getCombinedSootClassPath(OS os, String appClassPath, String sootClassPath) {
		String separator = os == OS.WINDOWS ? ";" : ":";
		return sootClassPath + separator + appClassPath;
	}

	public static List<de.fraunhofer.iem.secucheck.analysis.query.Method> getMethods(CompositeTaintFlowQuery flowQuery) {
		List<de.fraunhofer.iem.secucheck.analysis.query.Method> methods = new ArrayList<>();
		for (TaintFlowQuery singleFlow: flowQuery.getTaintFlowQueries()) {
			methods.addAll(getMethods(singleFlow));
		}
		return methods;
	}

	public static List<de.fraunhofer.iem.secucheck.analysis.query.Method> getMethods(TaintFlowQuery flowQuery) {
		List<de.fraunhofer.iem.secucheck.analysis.query.Method> methods = new ArrayList<>();
		flowQuery.getFrom().forEach(y -> methods.add((Method)y));
		flowQuery.getTo().forEach(y -> methods.add((Method)y));
		
		if (flowQuery.getNotThrough() != null)
			flowQuery.getNotThrough().forEach(y -> methods.add((Method)y));
		
		if (flowQuery.getThrough() != null)
			flowQuery.getThrough().forEach(y -> methods.add((Method)y));
		
		return methods;
	}

	public static SootMethod getSootMethod(boomerang.scene.Method method) {
		WrappedClass wrappedClass = method.getDeclaringClass();
		SootClass clazz = (SootClass) wrappedClass.getDelegate();
		return clazz.getMethod(method.getSubSignature());
	}

	public static SootMethod getSootMethod(de.fraunhofer.iem.secucheck.analysis.query.Method method) {
		String[] signatures = method.getSignature().split(":");
		SootClass sootClass = Scene.v().forceResolve(signatures[0], SootClass.BODIES);
		if (sootClass != null && signatures.length >= 2) {
			return sootClass.getMethodUnsafe(signatures[1].trim());
		}
		return null;
	}

	public static SootMethod findSourceMethodDefinition(TaintFlowQuery partialFlow,
			SootMethod method, Stmt actualStatement) {
		for (de.fraunhofer.iem.secucheck.analysis.query.Method sourceMethod : partialFlow.getFrom()) {
			String sourceSootSignature = "<" + sourceMethod.getSignature() + ">";
			if (method.getSignature().equals(sourceSootSignature)) {
				return method;
			} else if (actualStatement.containsInvokeExpr() && 
					actualStatement.toString().contains(sourceSootSignature)) {
				return actualStatement.getInvokeExpr().getMethodRef().tryResolve();
			}
		}
		return null;
	}

	public static SootMethod findSinkMethodDefinition(TaintFlowQuery partialFlow,
			SootMethod method, Stmt actualStatement) {
		for (de.fraunhofer.iem.secucheck.analysis.query.Method sinkMethod : partialFlow.getTo()) {
			String sinkSootSignature = "<" + sinkMethod.getSignature() + ">";
			if (actualStatement.containsInvokeExpr() &&
					actualStatement.toString().contains(sinkSootSignature)) {
				return actualStatement.getInvokeExpr().getMethodRef().tryResolve();
			}
		}
		return null;
	}

	public static void loadAllParticipantMethods(TaintFlowQueryImpl singleFlow) {
		// Resolve all methods. This is necessary if a flow participant is not part of
		// the user code...
		// See: https://github.com/secure-software-engineering/secucheck/issues/11
		for (Method method : Utility.getMethods(singleFlow)) {
			Utility.getSootMethod(method);
		}
	}
	
	public static String wrapInAngularBrackets(String value) {
		return "<" + value + ">";
	}
	
	public static boolean toStringEquals(Object object1, Object object2) {
		return object1.toString().equals(object2.toString());
	}
}
