import net.sf.jsqlparser.expression.*
import net.sf.jsqlparser.expression.operators.arithmetic.*
import net.sf.jsqlparser.expression.operators.conditional.AndExpression
import net.sf.jsqlparser.expression.operators.conditional.OrExpression
import net.sf.jsqlparser.expression.operators.relational.*
import net.sf.jsqlparser.schema.Column
import net.sf.jsqlparser.schema.Table
import net.sf.jsqlparser.statement.create.table.ColumnDefinition
import net.sf.jsqlparser.statement.create.table.CreateTable
import net.sf.jsqlparser.statement.delete.Delete
import net.sf.jsqlparser.statement.insert.Insert
import net.sf.jsqlparser.statement.select.*
import net.sf.jsqlparser.statement.update.Update
import net.sf.jsqlparser.statement.values.ValuesStatement

class TableNameFinder implements SelectVisitor, FromItemVisitor, ExpressionVisitor, ItemsListVisitor {
    private List<String> tables
    private Map<String, String> aliasMap
    private Map<String, String> conditionMap


    List<String> getTableList(Select select) {
        tables = new ArrayList<String>()
        aliasMap = new HashMap<String, String>()
        conditionMap = new HashMap<String, String>()
        select.getSelectBody().accept(this)
        PlainSelect ps = (PlainSelect) select.getSelectBody()
        FromItem fromItem = ps.getFromItem()
        String tableName = ''
        if (fromItem instanceof Table) {
            tableName = fromItem.getFullyQualifiedName().replace("`", "").replace("\"", "")
            if (fromItem.getAlias() != null) {
                aliasMap.put(fromItem.getAlias().getName(), tableName)
            }
            tables.add(tableName)
        }
        if (ps.getJoins() != null) {
            for (Join join : ps.getJoins()) {
                if (join.getRightItem() instanceof Table) {
                    String joinTableName = join.getRightItem().getFullyQualifiedName().replace("`", "").replace("\"", "")
                    if (join.getRightItem().getAlias() != null) {
                        aliasMap.put(join.getRightItem().getAlias().getName(), joinTableName)
                    }
                    tables.add(joinTableName)
                    Expression joinExpr = join.getOnExpression()
                    setJoinExpr(joinExpr)
                    ArrayList<Column> usingColumns = join.getUsingColumns()
                    setUsingCoulumns(usingColumns, tableName, joinTableName)
                    tableName = joinTableName
                }
            }
        }
        return tables
    }

    void setJoinExpr(Expression joinExpr) {
        if (joinExpr instanceof Parenthesis) {
            joinExpr = ((Parenthesis) joinExpr).getExpression()
            setJoinExpr(joinExpr)
        }
        else if (joinExpr instanceof AndExpression) {
            setJoinExpr(((AndExpression) joinExpr).getLeftExpression())
            setJoinExpr(((AndExpression) joinExpr).getRightExpression())
        }
        else if (joinExpr instanceof EqualsTo) {
            EqualsTo eq = (EqualsTo) joinExpr
            if (eq.getLeftExpression() instanceof Column && eq.getRightExpression() instanceof Column) {
                Column left = (Column) eq.getLeftExpression()
                Column right = (Column) eq.getRightExpression()
                if (left.getTable() != null && right.getTable() != null) {
                    String leftTable = left.getTable().getName().replace("`", "").replace("\"", "")
                    String leftColumnName = left.getColumnName().replace("INCREMENT_TEMP", "increment").replace("PUBLIC_TEMP", "public").replace("DEFAULT_TEMP", "default").replace("BINARY_TEMP", "binary").replace("`", "").replace("\"", "")
                    if (aliasMap.containsKey(leftTable)) {
                        leftTable = aliasMap.get(leftTable)
                    }
                    String rightTable = right.getTable().getName().replace("`", "").replace("\"", "")
                    String rightColumnName = right.getColumnName().replace("INCREMENT_TEMP", "increment").replace("PUBLIC_TEMP", "public").replace("DEFAULT_TEMP", "default").replace("BINARY_TEMP", "binary").replace("`", "").replace("\"", "")
                    if (aliasMap.containsKey(rightTable)) {
                        rightTable = aliasMap.get(rightTable)
                    }
                    if (leftTable != rightTable) {
                        if (QueryProcessing.tableRelations.get(leftTable + "." + leftColumnName) == null) {
                            QueryProcessing.tableRelations.put(leftTable + "." + leftColumnName, new HashSet<String>())
                        }
                        QueryProcessing.tableRelations.get(leftTable + "." + leftColumnName).add(rightTable + "." + rightColumnName)
                        if (QueryProcessing.tableRelations.get(rightTable + "." + rightColumnName) == null) {
                            QueryProcessing.tableRelations.put(rightTable + "." + rightColumnName, new HashSet<String>())
                        }
                        QueryProcessing.tableRelations.get(rightTable + "." + rightColumnName).add(leftTable + "." + leftColumnName)
                        System.out.println(leftTable + "." + leftColumnName + " = " + rightTable + "." + rightColumnName)
                        conditionMap.put(leftTable + "." + leftColumnName, rightTable + "." + rightColumnName)
                        conditionMap.put(rightTable + "." + rightColumnName, leftTable + "." + leftColumnName)
                    }
                }
            }
        }
        else {
            //TODO
        }
    }

    void setUsingCoulumns(ArrayList<Column> usingColumns, String leftTable, String rightTable) {
        if (leftTable == rightTable) {
            return
        }
        for (Column column in usingColumns) {
            String columnName = column.getColumnName().replace("INCREMENT_TEMP", "increment").replace("PUBLIC_TEMP", "public").replace("DEFAULT_TEMP", "default").replace("BINARY_TEMP", "binary").replace("`","").replace("\"", "")
            if (QueryProcessing.tableRelations.get(leftTable+"."+columnName) == null) {
                QueryProcessing.tableRelations.put(leftTable+"."+columnName, new HashSet<String>())
            }
            QueryProcessing.tableRelations.get(leftTable+"."+columnName).add(rightTable+"."+columnName)
            if (QueryProcessing.tableRelations.get(rightTable+"."+columnName) == null) {
                QueryProcessing.tableRelations.put(rightTable+"."+columnName, new HashSet<String>())
            }
            QueryProcessing.tableRelations.get(rightTable+"."+columnName).add(leftTable+"."+columnName)
            System.out.println(leftTable+"."+columnName+" = "+rightTable+"."+columnName)
            conditionMap.put(leftTable+"."+columnName, rightTable+"."+columnName)
            conditionMap.put(rightTable+"."+columnName, leftTable+"."+columnName)
        }
    }

    String getWhereList(Select select) {
        PlainSelect plainSelectStatement = (PlainSelect) select.getSelectBody()
        String items = ""
        Expression exp = plainSelectStatement.getWhere()
        if ((exp != null)) {
            items += "" + exp
        }
        return items
    }

    Map<String, String> getAliasMap() {
        return aliasMap
    }

    Map<String, String> getConditionMap() {
        return conditionMap
    }

    List<String> getTableList(Insert insert) {
        tables = new ArrayList<String>()
        aliasMap = new HashMap<String, String>()
        conditionMap = new HashMap<String, String>()
        insert.getTable().accept(this)
        tables.add(insert.getTable().getName().replace("`", "").replace("\"", ""))
        return tables
    }

    String getItemList(Insert insert) {
        String items = "";
        ItemsList list = insert.getItemsList()
        if (insert.isUseValues() && list != null)
            items += "" + list

        return items
    }

    List<String> getColumnList(List<Column> columns) {
        List<String> columnList = new ArrayList<String>()
        if (columns != null) {
            for (Column col : columns) {
                columnList.add(col.getColumnName().replace("INCREMENT_TEMP", "increment").replace("PUBLIC_TEMP", "public").replace("DEFAULT_TEMP", "default").replace("BINARY_TEMP", "binary").replace("`", "").replace("\"", ""))
            }
        }
        return columnList
    }

    List<Map.Entry<String, String>> getSelectItemList(List<SelectItem> selectItems) {
        List<Map.Entry<String, String>> selectItemList = new ArrayList<Map.Entry<String, String>>()
        if (selectItems != null) {
            for (SelectItem item : selectItems) {
                if (item instanceof AllColumns) {
                    for (String table : tables) {
                        for (String col : QueryProcessing.getTableColumns(table)) {
                            selectItemList.add(new AbstractMap.SimpleEntry<String, String>(table, col))
                        }
                    }
                }
                else if (item instanceof AllTableColumns) {
                    String table = ((AllTableColumns) item).getTable().getName().replace("`", "").replace("\"", "")
                    if (aliasMap.containsKey(table)) {
                        table = aliasMap.get(table)
                    }
                    for (String col : QueryProcessing.getTableColumns(table)) {
                        selectItemList.add(new AbstractMap.SimpleEntry<String, String>(table, col))
                    }
                }
                else if (item instanceof SelectExpressionItem ) {
                    if (((SelectExpressionItem) item).getExpression() instanceof Column) {
                        Column column = (Column) ((SelectExpressionItem) item).getExpression()
                        String columnName = column.getColumnName().replace("INCREMENT_TEMP", "increment").replace("PUBLIC_TEMP", "public").replace("DEFAULT_TEMP", "default").replace("BINARY_TEMP", "binary").replace("`", "").replace("\"", "")
                        String columnAlias = ""
                        if (item.getAlias() != null) {
                            columnAlias = item.getAlias().getName()
                        }
                        if (column.getTable() != null) {
                            String table = column.getTable().getName().replace("`", "").replace("\"", "")
                            if (aliasMap.containsKey(table)) {
                                table = aliasMap.get(table)
                            }
                            selectItemList.add(new AbstractMap.SimpleEntry<String, String>(table, columnName))
                        }
                        else {
                            for (String table in tables) {
                                if (QueryProcessing.containColumn(table, columnName)) {
                                    selectItemList.add(new AbstractMap.SimpleEntry<String, String>(table, columnName))
                                    break
                                }
                            }
                        }
                    }
                    else {
                        selectItemList.add(new AbstractMap.SimpleEntry<String, String>("", item.toString()))
                    }
                }
                else {
                    selectItemList.add(new AbstractMap.SimpleEntry<String, String>("", item.toString()))
                }
            }
        }
        return selectItemList
    }

    List<String> getItemList(List<Expression> items) {
        List<String> itemList = new ArrayList<String>()
        if (items != null) {
            for (Expression exp : items) {
                if (exp instanceof Parenthesis) {
                    exp = ((Parenthesis)exp).getExpression()
                }
                String expr = exp.toString()
                expr = expr.replace("'", "").replace("\"","")
                if (expr.startsWith("\$") || expr.contains('(')) {
                    itemList.add(expr)
                }
                else {
                    itemList.add(exp.toString().replace("INCREMENT_TEMP", "increment").replace("PUBLIC_TEMP", "public").replace("DEFAULT_TEMP", "default").replace("BINARY_TEMP", "binary"))
                }
            }
        }
        return itemList
    }

    List<String> getTableList(Update update) {
        tables = new ArrayList<String>()
        aliasMap = new HashMap<String, String>()
        conditionMap = new HashMap<String, String>()

        update.getTable().accept(this)
        Table table = update.getTable()
        String tableName = table.getName().replace("`", "").replace("\"", "")
        if (table.getAlias() != null) {
            aliasMap.put(table.getAlias().getName(), tableName)
        }
        tables.add(tableName)
        return tables
    }

    String getWhereList(Update update) {
        String items = ""
        Expression exp = update.getWhere()


        if ((exp != null)) {
            items += "" + exp.toString()
        }

        return items
    }

    String getExpList(Update update) {
        String items = ""
        List<Expression> exp = update.getExpressions()

        if ((!exp.isEmpty())) {
            items = PlainSelect.getStringList(exp, true, true)
        }

        return items
    }

    List<String> getTableList(Delete delete) {
        tables = new ArrayList<String>()
        aliasMap = new HashMap<String, String>()
        conditionMap = new HashMap<String, String>()
        delete.getTable().accept(this)
        tables.add(delete.getTable().getName().replace("`", "").replace("\"", ""))
        return tables
    }

    String getWhereList(Delete delete) {
        String items = ""
        Expression exp = delete.getWhere()
        if ((exp != null)) {
            items += "" + exp.toString()
        }

        return items
    }

    //Create
    ArrayList<ColDef> getCreateInfo(CreateTable createStatement) {


        ArrayList<ColDef> allColDef = new ArrayList<ColDef>()

        createStatement.getTable().accept(this)


        for (ColumnDefinition cd : createStatement.getColumnDefinitions()) {
            ColDef col = new ColDef()
            ArrayList<String> colSpec = new ArrayList<String>()
            ArrayList<String> argumentsList = new ArrayList<String>()
            String type = cd.getColDataType().getDataType()

            col.setTableName(createStatement.getTable().getName().replace("`", "").replace("\"", ""))
            argumentsList = cd.getColDataType().getArgumentsStringList()
            if (argumentsList.toString() != "null") {
                type = type+argumentsList.toString()
            }
            col.setColType(type)
            //TODO: we dont need this line anymore
            col.setArgumentsList(cd.getColDataType().getArgumentsStringList())
            col.setColName(cd.getColumnName().replace("INCREMENT_TEMP", "increment").replace("PUBLIC_TEMP", "public").replace("DEFAULT_TEMP", "default").replace("BINARY_TEMP", "binary").replace("`", "").replace("\"", ""))
            if (cd.getColumnSpecs() != null) {
                colSpec.addAll(cd.getColumnSpecs())
            }
            col.setColConstraints(colSpec)
            System.out.println("CREATE query is : " + col.toString())
            allColDef.add(col)
        }
        return allColDef
    }

    void visit(PlainSelect plainSelect) {
        if (plainSelect.getFromItem() != null) {
            plainSelect.getFromItem().accept(this); // to allow for a select query without from clause
        }

        if (plainSelect.getJoins() != null) {
            for (Join join : plainSelect.getJoins()) {
                join.getRightItem().accept(this)
            }
        }

        if (plainSelect.getWhere() != null) {
            plainSelect.getWhere().accept(this)
        }
    }


    @Override
    void visit(SubSelect subSelect) {
        subSelect.getSelectBody().accept((SelectVisitor)this)
    }

    @Override
    void visit(Addition addition) {
        visitBinaryExpression(addition)
    }

    @Override
    void visit(AndExpression andExpression) {
        visitBinaryExpression(andExpression)
    }

    @Override
    void visit(Between between) {
        between.getLeftExpression().accept(this)
        between.getBetweenExpressionStart().accept(this)
        between.getBetweenExpressionEnd().accept(this)
    }

    @Override
    void visit(Column tableColumn) {
    }

    @Override
    void visit(Division division) {
        visitBinaryExpression(division)
    }

    @Override
    void visit(IntegerDivision integerDivision) {

    }

    @Override
    void visit(DoubleValue doubleValue) {
    }

    @Override
    void visit(EqualsTo equalsTo) {
        visitBinaryExpression(equalsTo)
    }

    @Override
    void visit(Function function) {
    }

    @Override
    void visit(GreaterThan greaterThan) {
        visitBinaryExpression(greaterThan)
    }

    @Override
    void visit(GreaterThanEquals greaterThanEquals) {
        visitBinaryExpression(greaterThanEquals)
    }


    @Override
    void visit(IsNullExpression isNullExpression) {
    }

    @Override
    void visit(IsBooleanExpression isBooleanExpression) {

    }

    @Override
    void visit(JdbcParameter jdbcParameter) {
    }

    @Override
    void visit(LikeExpression likeExpression) {
        visitBinaryExpression(likeExpression)
    }

    @Override
    void visit(ExistsExpression existsExpression) {
        existsExpression.getRightExpression().accept(this)
    }

    @Override
    void visit(LongValue longValue) {
    }

    @Override
    void visit(MinorThan minorThan) {
        visitBinaryExpression(minorThan)
    }

    @Override
    void visit(MinorThanEquals minorThanEquals) {
        visitBinaryExpression(minorThanEquals)
    }

    @Override
    void visit(Multiplication multiplication) {
        visitBinaryExpression(multiplication)
    }

    @Override
    void visit(NotEqualsTo notEqualsTo) {
        visitBinaryExpression(notEqualsTo)
    }

    @Override
    void visit(BitwiseRightShift aThis) {

    }

    @Override
    void visit(BitwiseLeftShift aThis) {

    }

    @Override
    void visit(NullValue nullValue) {
    }

    @Override
    void visit(OrExpression orExpression) {
        visitBinaryExpression(orExpression)
    }

//    @Override
//    void visit(XorExpression xorExpression) {
//
//    }

    @Override
    void visit(Parenthesis parenthesis) {
        parenthesis.getExpression().accept(this)
    }

    @Override
    void visit(StringValue stringValue) {
    }

    @Override
    void visit(Subtraction subtraction) {
        visitBinaryExpression(subtraction)
    }

    void visitBinaryExpression(BinaryExpression binaryExpression) {
        binaryExpression.getLeftExpression().accept(this)
        if (binaryExpression.getRightExpression() instanceof SubSelect && this instanceof SelectVisitor) {
            binaryExpression.getRightExpression().accept((SelectVisitor)this)
        }
        else {
            binaryExpression.getRightExpression().accept(this)
        }
    }

    @Override
    void visit(ExpressionList expressionList) {
        for (Iterator iter = expressionList.getExpressions().iterator(); iter.hasNext(); ) {
            Expression expression = (Expression) iter.next()
            expression.accept(this)
        }

    }

    @Override
    void visit(NamedExpressionList namedExpressionList) {

    }


    @Override
    void visit(DateValue dateValue) {
    }

    @Override
    void visit(TimestampValue timestampValue) {
    }

    @Override
    void visit(TimeValue timeValue) {
    }

    @Override
    void visit(CaseExpression caseExpression) {
    }

    @Override
    void visit(WhenClause whenClause) {
    }

    @Override
    void visit(SubJoin subjoin) {
        subjoin.getLeft().accept(this)
    }

    @Override
    void visit(Concat arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(Matches arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(BitwiseAnd arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(BitwiseOr arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(BitwiseXor arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(MultiExpressionList arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(SignedExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(JdbcNamedParameter arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(InExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(FullTextSearch fullTextSearch) {

    }


    @Override
    void visit(AllComparisonExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(AnyComparisonExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(CastExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(Modulo arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(AnalyticExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(ExtractExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(IntervalExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(OracleHierarchicalExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(RegExpMatchOperator arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(JsonExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(RegExpMySQLOperator arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(UserVariable arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(NumericBind arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(KeepExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(MySQLGroupConcat arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(ValueListExpression valueList) {

    }

    @Override
    void visit(RowConstructor arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(Table arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(LateralSubSelect arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(ValuesList arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(SetOperationList arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(WithItem arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(ValuesStatement aThis) {

    }


    @Override
    void visit(HexValue arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(JsonOperator arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(OracleHint arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(TimeKeyExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(DateTimeLiteralExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(NotExpression arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(NextValExpression nextValExpression) {

    }

    @Override
    void visit(CollateExpression collateExpression) {

    }

    @Override
    void visit(SimilarToExpression similarToExpression) {

    }

    @Override
    void visit(ArrayExpression arrayExpression) {

    }

    @Override
    void visit(VariableAssignment variableAssignment) {

    }

    @Override
    void visit(XMLSerializeExpr xmlSerializeExpr) {

    }

    @Override
    void visit(TableFunction arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    void visit(ParenthesisFromItem aThis) {

    }


}
