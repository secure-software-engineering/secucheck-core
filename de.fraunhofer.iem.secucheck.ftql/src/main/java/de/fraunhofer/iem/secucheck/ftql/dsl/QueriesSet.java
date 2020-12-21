package de.fraunhofer.iem.secucheck.ftql.dsl;

import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.ftql.fluentInterface.query.TaintFlowQuery;

public class QueriesSet extends FluentTQLSpecificationImpl {
    //    private String queriesSetName;
    private final String categoryName;
    private final List<TaintFlowQuery> taintFlowQueries = new ArrayList<>();

    public QueriesSet(String categoryName) {
//        this.queriesSetName = queriesSetName;
        this.categoryName = categoryName;
    }

    public QueriesSet addTaintFlowQuery(TaintFlowQuery taintFlowQuery) {
        taintFlowQueries.add(taintFlowQuery);
        return this;
    }

/*    public String getName() {
        return queriesSetName;
    }
*/

    public String getCategoryName() {
        return categoryName;
    }

    public List<TaintFlowQuery> getTaintFlowQueries() {
        return taintFlowQueries;
    }
}
