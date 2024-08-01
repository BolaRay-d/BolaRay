package ast.expressions;

import ast.ASTNode;

public class Expression extends ASTNode
{
	private String operator = "";

	private boolean isForEachKeyOrValue = false;

	public Expression()
	{
	}

	public Expression(Expression other)
	{
		super(other);
		setOperator(other.operator);
	}

	public void replaceFirstChild(ASTNode node)
	{
		children.removeFirst();
		children.addFirst(node);
	}

	public void setOperator(String text)
	{
		operator = text;
	}

	public String getOperator()
	{
		return operator;
	}

	public boolean isForEachKeyOrValue() {
		return isForEachKeyOrValue;
	}

	public void setForEachKeyOrValue(boolean isForEachValue) {
		this.isForEachKeyOrValue = isForEachValue;
	}

}
