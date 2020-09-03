package de.fraunhofer.iem.secucheck.analysis;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.OS;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;

public class Utility {

	public static void ValidateCompositeFlowQueries(List<? super CompositeTaintFlowQueryImpl> flowQueries) 
			throws Exception {
		for (Object object: flowQueries) {
			
			if (object == null)
				throw new Exception("Please specify not null composite flow query.");
			
			CompositeTaintFlowQuery compositeFlow = (CompositeTaintFlowQuery) object;
			ValidateCompositeFlowQuery(compositeFlow);
		}
	}
	
	public static void ValidateCompositeFlowQuery(CompositeTaintFlowQuery flowQuery) 
			throws Exception {
		for (TaintFlowQuery singleFlow: flowQuery.getTaintFlowQueries()) {
			
			if (singleFlow == null)
				throw new Exception("Please specify not null single flow query.");
			
			ValidateSingleFlowQuery(singleFlow);
		}
	}
	
	public static void ValidateSingleFlowQuery(TaintFlowQuery flowQuery) throws Exception {
		if (flowQuery.getFrom() == null || flowQuery.getFrom().size() == 0)
			throw new Exception("For a valid taint flow query there must be some source specified.");
		if (flowQuery.getTo() == null ||flowQuery.getTo().size() == 0)
			throw new Exception("For a valid taint flow query there must be a sink specified.");
	}
	
	public static void executeSootRunnable(Runnable runable, String message) throws Exception {
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
		String separator = os == OS.Windows ? ";" : ":";
		return sootClassPath + separator + appClassPath;
	}
}
