package outputModules.common;

import cdg.CDG;
import cdg.CDGEdge;
import cfg.nodes.CFGNode;

import java.util.Map;

public abstract class CDGExporter
{
	public void addCDGToDatabase(CDG cdg)
	{

		for (CFGNode src : cdg.getVertices())
		{
			for (CDGEdge edge : cdg.outgoingEdges(src))
			{
				CFGNode dst = edge.getDestination();
				Map<String, Object> properties = edge.getProperties();
				if (!src.equals(dst))
				{
					addControlsEdge(src, dst, properties);
				}
			}
		}
	}

	protected abstract void addControlsEdge(CFGNode src, CFGNode dst, Map<String, Object> properties);

}
