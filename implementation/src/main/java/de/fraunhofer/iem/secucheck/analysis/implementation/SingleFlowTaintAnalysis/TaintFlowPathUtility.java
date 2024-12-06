package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis;

import boomerang.Query;
import de.fraunhofer.iem.secucheck.analysis.datastructures.DataFlowPath;
import de.fraunhofer.iem.secucheck.analysis.datastructures.TaintFlowPath;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.datastructure.BoomerangTaintFlowPath;

import javax.xml.crypto.Data;

/**
 * Utility for the TaintFlowPath
 *
 * @author Ranjith Krishnamurthy
 */
public abstract class TaintFlowPathUtility<T> {
    /**
     * Finds the given Query in the given TaintFlowPath and returns the node if found otherwise returns nulll
     *
     * @param rootNode Root node
     * @param value    Value to find in root node
     * @return Returns the found node otherwise null
     */
    public DataFlowPath<T> findNodeUsingDFS(DataFlowPath<T> rootNode, Query value) {
        if (rootNode.isLeafNode()) {
            if (rootNode.getNodeValue().equals(value)) {
                return rootNode;
            } else {
                return null;
            }
        }

        for (DataFlowPath<T> child : rootNode.getChildrenNodes()) {
            DataFlowPath<T> isFound = findNodeUsingDFS(child, value);

            if (isFound == null) {
                if (rootNode.getNodeValue().equals(value)) {
                    return rootNode;
                }
            } else {
                return isFound;
            }
        }

        return null;
    }

    /**
     * Get the root node of the given leaf node
     *
     * @param leafNode leaf node
     * @return Root node
     */
    protected DataFlowPath<T> getRootNode(DataFlowPath<T> leafNode) {
        if (leafNode.isRootNode())
            return leafNode;

        return getRootNode(leafNode.getParentNode());
    }

    /**
     * Prints the node and its children with indentation
     *
     * @param rootNode Node
     * @param indent   Indent spaces
     */
    private void printIndent(DataFlowPath<T> rootNode, String indent) {
        System.out.println(indent + rootNode.getNodeValue());

        if (!rootNode.isLeafNode()) {
            indent += "  ";
            for (DataFlowPath<T> query : rootNode.getChildrenNodes()) {
                printIndent(query, indent);
            }
        }
    }

    /**
     * Prints the given the node
     *
     * @param rootNode Node
     */
    public void print(DataFlowPath<T> rootNode) {
        printIndent(rootNode, "");
    }

    public abstract DataFlowPath<T> createSinglePathFromRootNode(DataFlowPath<T> leafNode);

    public abstract TaintFlowPath getTaintFlowPathFromRootNode(DataFlowPath<T> leafNode);
}
