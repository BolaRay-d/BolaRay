package outputModules.csv.exporters;

import cdg.CDG;
import cdg.CDGEdge;
import cfg.nodes.*;
import databaseNodes.EdgeTypes;
import outputModules.common.CDGExporter;
import outputModules.common.Writer;

import java.util.Map;

public class CSVCDGExporter extends CDGExporter
{

	@Override
	protected void addControlsEdge(CFGNode src, CFGNode dst, Map<String, Object> properties)
	{
		long srcId = getId(src);
		long dstId = getId(dst);
		Writer.addEdge(srcId, dstId, properties, EdgeTypes.CONTROLS);
	}

	private long getId(CFGNode node)
	{
		if (node instanceof ASTNodeContainer)
		{
			return Writer
					.getIdForObject(((ASTNodeContainer) node).getASTNode());
		}
		else
		{
			return Writer.getIdForObject(node);
		}
	}

	public void writeCDGEdges(CDG cdg) {
		for (CFGNode src : cdg.getVertices())
		{
			for (CDGEdge edge : cdg.outgoingEdges(src))
			{
				CFGNode dst = edge.getDestination();
				if (!src.equals(dst))
				{
					if( (src instanceof ASTNodeContainer || src instanceof CFGEntryNode || src instanceof CFGExitNode)
							&& (dst instanceof ASTNodeContainer || dst instanceof CFGEntryNode || dst instanceof CFGExitNode)) {

						// CFG nodes that are AST node containers have their ids stored in their AST node;
						// abstract nodes such as entry or exit nodes have their id set internally.
						Long srcId = (src instanceof ASTNodeContainer) ? ((ASTNodeContainer) src).getASTNode().getNodeId()
								: ((AbstractCFGNode) src).getNodeId();
						Long dstId = (dst instanceof ASTNodeContainer) ? ((ASTNodeContainer) dst).getASTNode().getNodeId()
								: ((AbstractCFGNode) dst).getNodeId();

						if (src instanceof ASTNodeContainer) {
							Writer.setIdForObject(((ASTNodeContainer) src).getASTNode(), srcId);
						}
						else {
							Writer.setIdForObject(src, srcId);
						}
						if (dst instanceof ASTNodeContainer) {
							Writer.setIdForObject(((ASTNodeContainer) dst).getASTNode(), dstId);
						}
						else {
							Writer.setIdForObject(dst, dstId);
						}
						Map<String, Object> properties = edge.getProperties();
						addControlsEdge(src, dst, properties);
					}
				}
			}
		}

		// clean up
		Writer.reset();
	}

}
