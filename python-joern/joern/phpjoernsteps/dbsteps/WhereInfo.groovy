@GrabResolver(name='custom', root='https://repo.maven.apache.org/maven2')
@Grab('commons-net:commons-net:3.3')
@Grab('com.github.jsqlparser:jsqlparser:4.0')

import net.sf.jsqlparser.expression.Expression
import net.sf.jsqlparser.expression.Function
import net.sf.jsqlparser.expression.JdbcNamedParameter
import net.sf.jsqlparser.expression.JdbcParameter
import net.sf.jsqlparser.expression.LongValue
import net.sf.jsqlparser.expression.Parenthesis
import net.sf.jsqlparser.expression.StringValue
import net.sf.jsqlparser.expression.ArrayExpression
import net.sf.jsqlparser.expression.operators.conditional.AndExpression
import net.sf.jsqlparser.expression.operators.conditional.OrExpression
import net.sf.jsqlparser.expression.operators.relational.EqualsTo
import net.sf.jsqlparser.expression.operators.relational.ExpressionList
import net.sf.jsqlparser.expression.operators.relational.InExpression
import net.sf.jsqlparser.expression.operators.relational.ItemsList
import net.sf.jsqlparser.schema.Column

class WhereInfo extends QueryInfo{
    List<Object> conditionCols

    List<String> conditionOps

    List<Object> conditionVals

    WhereInfo() {
        super()
        conditionCols = new ArrayList<>()
        conditionOps = new ArrayList<>()
        conditionVals = new ArrayList<>()
    }

    WhereInfo(WhereInfo whereInfo) {
        super(whereInfo)
        conditionCols = whereInfo.conditionCols
        conditionOps = whereInfo.conditionOps
        conditionVals = whereInfo.conditionVals
    }

    List<Object> getConditionCols() {
        return conditionCols
    }

    List<String> getConditionOps() {
        return conditionOps
    }

    List<Object> getConditionVals() {
        return conditionVals
    }

    void parseWhereClause(Expression whereClause) {
        if (whereClause != null) {
            if (whereClause instanceof AndExpression) {
                parseWhereClause(((AndExpression) whereClause).getLeftExpression())
                parseWhereClause(((AndExpression) whereClause).getRightExpression())
            }
            else if (whereClause instanceof OrExpression) {
                parseWhereClause(((OrExpression) whereClause).getLeftExpression())
                parseWhereClause(((OrExpression) whereClause).getRightExpression())
            }
            else if (whereClause instanceof EqualsTo) {
                Expression leftExpression = ((EqualsTo) whereClause).getLeftExpression()
                Expression rightExpression = ((EqualsTo) whereClause).getRightExpression()
                if (rightExpression instanceof Parenthesis) {
                    rightExpression = ((Parenthesis) rightExpression).getExpression()
                }
                if (leftExpression != null && leftExpression instanceof Column) {
                    if (rightExpression != null && (rightExpression instanceof StringValue || rightExpression instanceof LongValue
                            || rightExpression instanceof JdbcNamedParameter
                            || rightExpression instanceof JdbcParameter
                            || rightExpression instanceof ArrayExpression
                            || rightExpression instanceof Function
                    )) {
                        Column column = (Column)leftExpression
                        String columnName = column.getColumnName().replace("INCREMENT_TEMP", "increment").replace("PUBLIC_TEMP", "public").replace("DEFAULT_TEMP", "default").replace("BINARY_TEMP", "binary").replace("`", "").replace("\"", "")
                        if (column.getTable() != null) {
                            String table = column.getTable().getName().replace("`", "").replace("\"", "")
                            if (aliasMap && aliasMap.containsKey(table)) {
                                table = aliasMap.get(table)
                            }
                            conditionCols.add(table + "." + columnName)
                        }
                        else {
                            for (String table in tablelist) {
                                if (QueryProcessing.containColumn(table, columnName)) {
                                    conditionCols.add(table+"."+columnName)
                                    break
                                }
                            }
                        }
                        conditionOps.add("=")
                        String rExpr = rightExpression.toString().replace("'", "").replace("\"", "")
                        if (rExpr.startsWith("\$") || rExpr.contains('(')) {
                            conditionVals.add(rExpr)
                        }
                        else {
                            conditionVals.add(rightExpression.toString())
                        }
                    }
                    else if (rightExpression != null && rightExpression instanceof Column) {
                        Column leftColumn = (Column)leftExpression
                        Column rightColumn = (Column)rightExpression
                        String leftTable = null
                        String rightTable = null
                        String leftColumnName = leftColumn.getColumnName().replace("INCREMENT_TEMP", "increment").replace("PUBLIC_TEMP", "public").replace("DEFAULT_TEMP", "default").replace("BINARY_TEMP", "binary").replace("`", "").replace("\"", "")
                        if (leftColumn.getTable() != null) {
                            leftTable = leftColumn.getTable().getName().replace("`", "").replace("\"", "")
                            if (aliasMap && aliasMap.containsKey(leftTable)) {
                                leftTable = aliasMap.get(leftTable)
                            }
                            conditionCols.add(leftTable + "." + leftColumnName)
                        }
                        else {
                            for (String table in tablelist) {
                                if (QueryProcessing.containColumn(table, leftColumnName)) {
                                    conditionCols.add(table+"."+leftColumnName)
                                    break
                                }
                            }
                        }
                        conditionOps.add("=")
                        if (rightColumn.getTable() != null) {
                            rightTable = rightColumn.getTable().getName().replace("`", "").replace("\"", "")
                            if (aliasMap && aliasMap.containsKey(rightTable)) {
                                rightTable = aliasMap.get(rightTable)
                            }
                        }
                        String rightColumnName =rightColumn.getColumnName().replace("INCREMENT_TEMP", "increment").replace("PUBLIC_TEMP", "public").replace("DEFAULT_TEMP", "default").replace("BINARY_TEMP", "binary").replace("`", "")
                        if (rightColumnName.replace("\"","").startsWith("\$")) {
                            rightColumnName = rightColumnName.replace("\"","")
                        }
                        conditionVals.add(rightTable?rightTable + "." + rightColumnName:rightColumnName)
                        if (leftTable != null && rightTable != null && leftTable != rightTable) {
                            if (QueryProcessing.tableRelations.get(leftTable+"."+leftColumnName) == null) {
                                QueryProcessing.tableRelations.put(leftTable+"."+leftColumnName, new HashSet<>())
                            }
                            QueryProcessing.tableRelations.get(leftTable+"."+leftColumnName).add(rightTable+"."+rightColumnName)
                            if (QueryProcessing.tableRelations.get(rightTable+"."+rightColumnName) == null) {
                                QueryProcessing.tableRelations.put(rightTable+"."+rightColumnName, new HashSet<>())
                            }
                            QueryProcessing.tableRelations.get(rightTable+"."+rightColumnName).add(leftTable+"."+leftColumnName)
                            System.out.println(leftTable+"."+leftColumnName+" = "+rightTable+"."+rightColumnName)
                        }
                    }
                    else {
                        //TODO
                    }
                }
            }
            else if (whereClause instanceof InExpression) {
                Expression leftExpression = ((InExpression) whereClause).getLeftExpression()
                ItemsList rightExpression = ((InExpression) whereClause).getRightItemsList()
                if (leftExpression != null && leftExpression instanceof Column &&
                        rightExpression != null && rightExpression instanceof ExpressionList) {
                    Column column = (Column)leftExpression
                    String columnName = column.getColumnName().replace("INCREMENT_TEMP", "increment").replace("PUBLIC_TEMP", "public").replace("DEFAULT_TEMP", "default").replace("BINARY_TEMP", "binary").replace("`", "").replace("\"", "")
                    if (column.getTable() != null) {
                        String table = column.getTable().getName().replace("`", "").replace("\"", "")
                        if (aliasMap && aliasMap.containsKey(table)) {
                            table = aliasMap.get(table)
                        }
                        conditionCols.add(table + "." + columnName)
                    }
                    else {
                        for (String table in tablelist) {
                            if (QueryProcessing.containColumn(table, columnName)) {
                                conditionCols.add(table+"."+columnName)
                                break
                            }
                        }
//                        conditionCols.add(tablelist.get(0) + "." + column.getColumnName().replace("`", ""))
                    }
                    if (((InExpression) whereClause).isNot()) {
                        conditionOps.add("NOT IN")
                    }
                    else {
                        conditionOps.add("IN")
                    }
                    List<String> vals = new ArrayList<>()
                    for (Expression expr : ((ExpressionList)rightExpression).getExpressions()) {
                        String val = expr.toString().replace("'", "").replace("\"", "")
                        if (val.startsWith("\$") || val.contains('(')) {
                            vals.add(val)
                        }
                        else {
                            vals.add(expr.toString())
                        }
                    }
                    conditionVals.add(vals)
                }
            }
            else if (whereClause instanceof Parenthesis) {
                parseWhereClause(((Parenthesis) whereClause).getExpression())
            }
            else {
                //TODO
            }
        }
    }
}

