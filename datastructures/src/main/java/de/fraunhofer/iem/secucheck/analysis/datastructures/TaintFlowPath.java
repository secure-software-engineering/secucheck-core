package de.fraunhofer.iem.secucheck.analysis.datastructures;

import java.util.ArrayList;
import java.util.List;

public class TaintFlowPath implements DataFlowPath<TaintFlowPathNode> {
    private final TaintFlowPathNode query;
    private final List<DataFlowPath<TaintFlowPathNode>> childrenNodes;
    private final TaintFlowPath parentNode;
    private final boolean isRootNode;
    private final boolean isNodeSink;
    private boolean isLeafNode;

    public TaintFlowPath(
            TaintFlowPathNode query,
            TaintFlowPath parentNode,
            boolean isRootNode,
            boolean isNodeSink) {
        this.query = query;
        this.childrenNodes = new ArrayList<DataFlowPath<TaintFlowPathNode>>();
        this.parentNode = parentNode;
        this.isRootNode = isRootNode;
        this.isNodeSink = isNodeSink;
        this.isLeafNode = true;
    }

    public void addNewChild(TaintFlowPath nextNode) {
        childrenNodes.add(nextNode);
        isLeafNode = false;
    }

    @Override
    public TaintFlowPathNode getNodeValue() {
        return query;
    }

    @Override
    public List<DataFlowPath<TaintFlowPathNode>> getChildrenNodes() {
        return childrenNodes;
    }

    @Override
    public DataFlowPath<TaintFlowPathNode> getParentNode() {
        return parentNode;
    }

    @Override
    public boolean isRootNode() {
        return isRootNode;
    }

    @Override
    public boolean isNodeSink() {
        return isNodeSink;
    }

    @Override
    public boolean isLeafNode() {
        return isLeafNode;
    }
}
