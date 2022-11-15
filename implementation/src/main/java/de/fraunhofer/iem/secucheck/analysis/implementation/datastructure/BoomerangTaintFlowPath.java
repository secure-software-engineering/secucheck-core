package de.fraunhofer.iem.secucheck.analysis.implementation.datastructure;

import boomerang.Query;
import de.fraunhofer.iem.secucheck.analysis.datastructures.TaintFlowPath;

import java.util.ArrayList;
import java.util.List;

/**
 * TaintFlow path for the Boomerang result
 *
 * @author Ranjith Krishnamurthy
 */
public class BoomerangTaintFlowPath implements TaintFlowPath {
    private final Query query;
    private final List<TaintFlowPath> childrenNodes;
    private final BoomerangTaintFlowPath parentNode;
    private final boolean isRootNode;
    private final boolean isNodeSink;
    private boolean isLeafNode;

    public BoomerangTaintFlowPath(
            Query query,
            BoomerangTaintFlowPath parentNode,
            boolean isRootNode,
            boolean isNodeSink) {
        this.query = query;
        this.childrenNodes = new ArrayList<TaintFlowPath>();
        this.parentNode = parentNode;
        this.isRootNode = isRootNode;
        this.isNodeSink = isNodeSink;
        this.isLeafNode = true;
    }

    public void addNewChild(BoomerangTaintFlowPath nextNode) {
        childrenNodes.add(nextNode);
        isLeafNode = false;
    }

    @Override
    public Object getNodeValue() {
        return query;
    }

    @Override
    public List<TaintFlowPath> getChildrenNodes() {
        return childrenNodes;
    }

    @Override
    public TaintFlowPath getParentNode() {
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
