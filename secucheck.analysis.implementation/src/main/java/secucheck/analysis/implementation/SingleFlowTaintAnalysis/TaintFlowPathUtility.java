package secucheck.analysis.implementation.SingleFlowTaintAnalysis;

import boomerang.Query;
import secucheck.analysis.datastructures.TaintFlowPath;
import secucheck.analysis.implementation.SingleFlowTaintAnalysis.datastructure.BoomerangTaintFlowPath;

/**
 * Utility for the TaintFlowPath
 *
 */
public class TaintFlowPathUtility {
    /**
     * Finds the given Query in the given TaintFlowPath and returns the node if found otherwise returns nulll
     *
     * @param rootNode Root node
     * @param value    Value to find in root node
     * @return Returns the found node otherwise null
     */
    public static TaintFlowPath findNodeUsingDFS(TaintFlowPath rootNode, Query value) {
        if (rootNode.isLeafNode()) {
            if (rootNode.getNodeValue().equals(value)) {
                return rootNode;
            } else {
                return null;
            }
        }

        for (TaintFlowPath child : rootNode.getChildrenNodes()) {
            TaintFlowPath isFound = findNodeUsingDFS(child, value);

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
     * Creates a single path from the source to given sink node and returns its sink node
     *
     * @param leafNode Sink node
     * @return Single path but returns the sink node
     */
    private static TaintFlowPath createSinglePath(TaintFlowPath leafNode) {
        if (leafNode.isRootNode()) {
            return new BoomerangTaintFlowPath((Query) leafNode.getNodeValue(), null, true, false);
        }


        BoomerangTaintFlowPath parentNode = (BoomerangTaintFlowPath) createSinglePath(leafNode.getParentNode());
        BoomerangTaintFlowPath childNode = new BoomerangTaintFlowPath((Query) leafNode.getNodeValue(), parentNode, false, leafNode.isNodeSink());
        parentNode.addNewChild(childNode);
        return childNode;
    }

    /**
     * Get the root node of the given leaf node
     *
     * @param leafNode leaf node
     * @return Root node
     */
    private static TaintFlowPath getRootNode(TaintFlowPath leafNode) {
        if (leafNode.isRootNode())
            return leafNode;

        return getRootNode(leafNode.getParentNode());
    }

    /**
     * Creates a single path from the source to given sink node and returns its root node
     *
     * @param leafNode Sink node
     * @return Single path
     */
    public static BoomerangTaintFlowPath createSinglePathFromRootNode(TaintFlowPath leafNode) {
        BoomerangTaintFlowPath singleTaintFlowLeafNode = (BoomerangTaintFlowPath) createSinglePath(leafNode);

        return (BoomerangTaintFlowPath) getRootNode(singleTaintFlowLeafNode);
    }

    /**
     * Prints the node and its children with indentation
     *
     * @param rootNode Node
     * @param indent   Indent spaces
     */
    private static void printIndent(TaintFlowPath rootNode, String indent) {
        System.out.println(indent + rootNode.getNodeValue());

        if (!rootNode.isLeafNode()) {
            indent += "  ";
            for (TaintFlowPath query : rootNode.getChildrenNodes()) {
                printIndent(query, indent);
            }
        }
    }

    /**
     * Prints the given the node
     *
     * @param rootNode Node
     */
    public static void print(TaintFlowPath rootNode) {
        printIndent(rootNode, "");
    }
}
