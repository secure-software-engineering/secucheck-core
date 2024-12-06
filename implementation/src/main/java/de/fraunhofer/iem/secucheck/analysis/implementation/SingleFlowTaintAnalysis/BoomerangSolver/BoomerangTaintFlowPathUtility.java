package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver;

import boomerang.Query;
import de.fraunhofer.iem.secucheck.analysis.datastructures.DataFlowPath;
import de.fraunhofer.iem.secucheck.analysis.datastructures.TaintFlowPath;
import de.fraunhofer.iem.secucheck.analysis.datastructures.TaintFlowPathNode;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.TaintFlowPathUtility;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.datastructure.BoomerangTaintFlowPath;
import lombok.val;

/**
 * Utility for the TaintFlowPath
 *
 * @author Ranjith Krishnamurthy
 */
public class BoomerangTaintFlowPathUtility extends TaintFlowPathUtility<Query> {
    /**
     * Creates a single path from the source to given sink node and returns its sink node
     *
     * @param leafNode Sink node
     * @return Single path but returns the sink node
     */
    private BoomerangTaintFlowPath createSinglePath(DataFlowPath<Query> leafNode) {
        if (leafNode.isRootNode()) {
            return new BoomerangTaintFlowPath(leafNode.getNodeValue(), null, true, false);
        }


        BoomerangTaintFlowPath parentNode = createSinglePath(leafNode.getParentNode());
        BoomerangTaintFlowPath childNode = new BoomerangTaintFlowPath(leafNode.getNodeValue(), parentNode, false, leafNode.isNodeSink());
        parentNode.addNewChild(childNode);
        return childNode;
    }

    /**
     * Creates a single path from the source to given sink node and returns its root node
     *
     * @param leafNode Sink node
     * @return Single path
     */
    public BoomerangTaintFlowPath createSinglePathFromRootNode(DataFlowPath<Query> leafNode) {
        BoomerangTaintFlowPath singleTaintFlowLeafNode = createSinglePath(leafNode);

        return (BoomerangTaintFlowPath) getRootNode(singleTaintFlowLeafNode);
    }

    private void getTaintFlowPath(BoomerangTaintFlowPath node, TaintFlowPath parentNode) {
        val sourceStmt = node.getNodeValue().cfgEdge().getStart();
        val sig = "<" + sourceStmt.getMethod().getDeclaringClass().getFullyQualifiedName() + ": " + sourceStmt.getMethod().getSubSignature() + ">";

        val taintFlowPathNode = new TaintFlowPathNode(
                sig,
                sourceStmt.getStartLineNumber(),
                sourceStmt.toString()
        );

        val currentNode = new TaintFlowPath(taintFlowPathNode, parentNode, false, false);
        parentNode.addNewChild(currentNode);

        if (node.isLeafNode()) {
            return;
        }

        for (val child : node.getChildrenNodes()) {
            getTaintFlowPath((BoomerangTaintFlowPath) child, currentNode);
        }
    }

    @Override
    public TaintFlowPath getTaintFlowPathFromRootNode(DataFlowPath<Query> rootNode) {
        val sourceStmt = rootNode.getNodeValue().cfgEdge().getStart();
        val sig = "<" + sourceStmt.getMethod().getDeclaringClass().getFullyQualifiedName() + ": " + sourceStmt.getMethod().getSubSignature() + ">";

        val taintFlowPathNode = new TaintFlowPathNode(
                sig,
                sourceStmt.getStartLineNumber(),
                sourceStmt.toString()
        );

        val rootTaintFlowPath = new TaintFlowPath(taintFlowPathNode, null, true, false);

        for (val child : rootNode.getChildrenNodes()) {
            getTaintFlowPath((BoomerangTaintFlowPath) child, rootTaintFlowPath);
        }
        return rootTaintFlowPath;
    }
}
