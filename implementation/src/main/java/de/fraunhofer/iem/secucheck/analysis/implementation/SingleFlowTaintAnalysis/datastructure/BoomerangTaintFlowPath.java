package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.datastructure;

import boomerang.ForwardQuery;
import boomerang.Query;
import de.fraunhofer.iem.secucheck.analysis.datastructures.DataFlowPath;
import de.fraunhofer.iem.secucheck.analysis.datastructures.TaintFlowPath;

import java.util.ArrayList;
import java.util.List;

/**
 * TaintFlow path for the Boomerang result
 *
 * @author Ranjith Krishnamurthy
 */
public class BoomerangTaintFlowPath implements DataFlowPath<Query> {
    private final Query query;
    private final List<DataFlowPath<Query>> childrenNodes;
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
        this.childrenNodes = new ArrayList<DataFlowPath<Query>>();
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
    public Query getNodeValue() {
        return query;
    }

    @Override
    public List<DataFlowPath<Query>> getChildrenNodes() {
        return childrenNodes;
    }

    @Override
    public DataFlowPath<Query> getParentNode() {
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
