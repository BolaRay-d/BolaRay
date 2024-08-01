package cdg;

import graphutils.IncidenceListGraph;
import cfg.nodes.CFGNode;

public class CDG extends IncidenceListGraph<CFGNode, CDGEdge>
{

	void addEdge(CFGNode source, CFGNode destination, String label)
	{
		addEdge(new CDGEdge(source, destination, label));
	}

}
