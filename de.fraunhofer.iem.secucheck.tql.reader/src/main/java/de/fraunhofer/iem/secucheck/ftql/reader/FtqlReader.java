package de.fraunhofer.iem.secucheck.ftql.reader;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.query.TaintFlowQuery;

public class FtqlReader {

   public static List<CompositeTaintFlowQueryImpl> getSecucheckCoreQueries(String tqlSpecPath) {
	   List<TaintFlowQuery> taintFlowSpecs = FtqlUtility.getTaintFLowQuerySpecs(tqlSpecPath);
	   return FtqlToCoreUtility.getCompositeTaintFlowQueries(taintFlowSpecs);
   }
   
}
