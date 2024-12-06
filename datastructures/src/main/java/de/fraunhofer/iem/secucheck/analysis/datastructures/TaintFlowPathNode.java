package de.fraunhofer.iem.secucheck.analysis.datastructures;

import lombok.Data;

@Data
public class TaintFlowPathNode {
    private final String methodName;
    private final int lineNumber;
    private final String stmt;
}
