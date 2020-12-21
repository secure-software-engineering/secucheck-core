package de.fraunhofer.iem.secucheck.ftql.dsl;

import de.fraunhofer.iem.secucheck.ftql.fluentInterface.query.TaintFlowQuery;

public class TaintFlowWithReportLocation {
    private final TaintFlowQueryImpl taintFlowQuery;

    public TaintFlowWithReportLocation(TaintFlowQuery taintFlowQuery) {
        this.taintFlowQuery = (TaintFlowQueryImpl) taintFlowQuery;
    }

    public TaintFlowQuery build() {
        return taintFlowQuery;
    }
}
