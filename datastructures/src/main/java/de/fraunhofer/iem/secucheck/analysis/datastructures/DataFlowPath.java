package de.fraunhofer.iem.secucheck.analysis.datastructures;

import java.util.List;

/**
 * TaintFlowPath
 *
 * @author Ranjith Krishnamurthy
 */
public interface DataFlowPath<T> {
    /**
     * Nodes value
     *
     * @return Nodes value
     */
    public T getNodeValue();

    /**
     * List of children node
     *
     * @return Children node
     */
    public List<DataFlowPath<T>> getChildrenNodes();

    /**
     * Parent node
     *
     * @return Parent node
     */
    public DataFlowPath<T> getParentNode();

    /**
     * Is Root node otherwise false
     *
     * @return Root node or not
     */
    public boolean isRootNode();

    /**
     * Is sink node otherwise false
     *
     * @return Sink node or not
     */
    public boolean isNodeSink();

    /**
     * Is leaf node otherwise false
     *
     * @return Leaf node or not
     */
    public boolean isLeafNode();


}
