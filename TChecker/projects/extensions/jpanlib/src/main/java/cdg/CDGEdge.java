package cdg;

import java.util.HashMap;
import java.util.Map;

import cfg.nodes.CFGNode;
import graphutils.Edge;

public class CDGEdge extends Edge<CFGNode>
{

	private String label;

	private Map<String, Object> properties;

	public CDGEdge(CFGNode source, CFGNode destination, String label)
	{
		super(source, destination);
		this.label = label;
	}

	public String getLabel()
	{
		return this.label;
	}

	@Override
	public Map<String, Object> getProperties()
	{
		if (this.properties == null)
		{
			this.properties = new HashMap<String, Object>();
			this.properties.put("var", label);
		}
		return this.properties;
	}

	@Override
	public int hashCode()
	{
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((label == null) ? 0 : label.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj)
	{
		if (this == obj)
		{
			return true;
		}
		if (!super.equals(obj))
		{
			return false;
		}
		if (!(obj instanceof CDGEdge))
		{
			return false;
		}
		CDGEdge other = (CDGEdge) obj;
		if (label == null)
		{
			if (other.label != null)
			{
				return false;
			}
		}
		else if (!label.equals(other.label))
		{
			return false;
		}
		return true;
	}

	@Override
	public String toString()
	{
		return getSource() + " ==[" + getLabel() + "]==> " + getDestination();
	}


	@Override
	public CDGEdge reverse()
	{
		return new CDGEdge(getDestination(), getSource(), getLabel());

	}

}
