package de.fraunhofer.iem.secucheck.ftql.dsl;

import de.fraunhofer.iem.secucheck.ftql.fluentInterface.query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.taintflowpack.FlowParticipant;

public class TaintFlowQueryBuilder {
    private TaintFlowQueryImpl taintFlowQuery = null;

    public TaintFlowQueryBuilder() {
        if (taintFlowQuery == null)
            taintFlowQuery = new TaintFlowQueryImpl();
    }

    public TaintFlowQueryBuilder(TaintFlowQuery taintFlowQuery) {
        this.taintFlowQuery = (TaintFlowQueryImpl) taintFlowQuery;
    }

    public FlowFromSource from(FlowParticipant source) {
        TaintFlowImpl singleTaintFlow = new TaintFlowImpl();

        singleTaintFlow.setFrom(source);
        return new FlowFromSource(taintFlowQuery, singleTaintFlow);
    }
}
