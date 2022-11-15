package de.fraunhofer.iem.secucheck.analysis.datastructures;

import java.util.List;

/**
 * TaintFlowPath
 *
 * @author Ranjith Krishnamurthy
 */
public interface TaintFlowPath {
    /**
     * Nodes value
     *
     * @return Nodes value
     */
    public Object getNodeValue();

    /**
     * List of children node
     *
     * @return Children node
     */
    public List<TaintFlowPath> getChildrenNodes();

    /**
     * Parent node
     *
     * @return Parent node
     */
    public TaintFlowPath getParentNode();

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
