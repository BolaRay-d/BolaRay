import net.sf.jsqlparser.JSQLParserException
import net.sf.jsqlparser.expression.operators.relational.ExpressionList
import net.sf.jsqlparser.expression.operators.relational.ItemsList
import net.sf.jsqlparser.expression.operators.relational.MultiExpressionList
import net.sf.jsqlparser.parser.CCJSqlParserManager
import net.sf.jsqlparser.statement.Statement
import net.sf.jsqlparser.statement.create.table.CreateTable
import net.sf.jsqlparser.statement.delete.Delete
import net.sf.jsqlparser.statement.insert.Insert
import net.sf.jsqlparser.statement.select.PlainSelect
import net.sf.jsqlparser.statement.select.Select
import net.sf.jsqlparser.statement.select.SelectBody
import net.sf.jsqlparser.statement.update.Update

class QueryProcessing {

    static ArrayList<QueryInfo> querys = new ArrayList<QueryInfo>()

    static HashMap<String, ArrayList<ColDef>> tables = new HashMap<String, ArrayList<ColDef>>()

    static HashMap<String, HashSet<String>> tableRelations = new HashMap<String, HashSet<String>>()

    static HashMap<String, String> valColumnRelations = new HashMap<String, String>()

    static void ParseQuery(String sql) {
        System.out.println("\n****************************************************************************************\n" + sql + "\n")
        CCJSqlParserManager pm = new CCJSqlParserManager()
        try {
            Statement statement = pm.parse(new StringReader(sql))
            if (statement instanceof Select) {
                Select selectStatement = (Select) statement
                TableNameFinder tablesNamesFinder = new TableNameFinder()
                List<String> tableList = tablesNamesFinder.getTableList(selectStatement)
                SelectBody selectBody = selectStatement.getSelectBody()
                if (selectBody != null && selectBody instanceof PlainSelect) {
                    PlainSelect plainSelectStatement = (PlainSelect) selectBody
                    List<Map.Entry<String, String>> selectItemList = tablesNamesFinder.getSelectItemList(plainSelectStatement.getSelectItems())
                    String whereList = tablesNamesFinder.getWhereList(selectStatement)
                    Map<String, String> aliasMap = tablesNamesFinder.getAliasMap()
                    Map<String, String> conditionMap = tablesNamesFinder.getConditionMap()

                    SelectInfo qi = new SelectInfo()
                    qi.setqType(QueryInfo.QueryType.SELECT)
                    qi.setTNames(tableList)
                    qi.setWhere(whereList)
                    qi.setAliasMap(aliasMap)
                    qi.setSelectItemList(selectItemList)
                    qi.parseWhereClause(plainSelectStatement.getWhere())
                    qi.setConditionMap(conditionMap)
                    querys.add(qi)

                    System.out.println(qi)
                }
                else {
                    System.out.println("selectBody type is " + selectBody.getClass().getName())
                }
            }
            else if (statement instanceof Insert) {
                Insert insertStatement = (Insert) statement
                TableNameFinder tablesNamesFinder = new TableNameFinder()
                List<String> tableList = tablesNamesFinder.getTableList(insertStatement)
                List<String> colList = null
                List<String> itemList = null
                ItemsList itemsList
                if (insertStatement.isUseValues()) {
                    colList = tablesNamesFinder.getColumnList(insertStatement.getColumns())
                    itemsList = insertStatement.getItemsList()
                    if (itemsList instanceof ExpressionList) {
                        itemList = tablesNamesFinder.getItemList(((ExpressionList) itemsList).getExpressions())
                    }
                    else if (itemsList instanceof MultiExpressionList) {
                        List<String> eachIteamList
                        for (ExpressionList expressionList in ((MultiExpressionList)itemsList).getExprList()) {
                            eachIteamList = tablesNamesFinder.getItemList(expressionList.getExpressions())
                            if (itemList == null) {
                                itemList = eachIteamList
                            }
                            else {
                                itemList.addAll(eachIteamList)
                            }
                        }
                    }
                }
                else if (insertStatement.isUseSet()) {
                    colList = tablesNamesFinder.getColumnList(insertStatement.getSetColumns())
                    itemList = tablesNamesFinder.getItemList(insertStatement.getSetExpressionList())
                }
                else {
                    System.out.println("Error in parsing the insert query: " + sql + "\n")
                    return
                }
                if (colList != null && colList.isEmpty()) {
                    colList = getTableColumns(tableList.get(0))
                }

                InsertInfo qi = new InsertInfo()
                qi.setqType(QueryInfo.QueryType.INSERT)
                qi.setTNames(tableList)
                qi.setColNames(colList)
                qi.setItemNames(itemList)
                querys.add(qi)

                System.out.println(qi)
            }
            else if (statement instanceof Update) {
                Update updateStatement = (Update) statement
                TableNameFinder tablesNamesFinder = new TableNameFinder()
                List<String> tableList = tablesNamesFinder.getTableList(updateStatement)
                List<String> colList = tablesNamesFinder.getColumnList(updateStatement.getColumns())
                List<String> itemList = tablesNamesFinder.getItemList(updateStatement.getExpressions())
                String whereList = tablesNamesFinder.getWhereList(updateStatement)
                Map<String, String> aliasMap = tablesNamesFinder.getAliasMap()

                UpdateInfo qi = new UpdateInfo()
                qi.setqType(QueryInfo.QueryType.UPDATE)
                qi.setTNames(tableList)
                qi.setColNames(colList)
                qi.setItemNames(itemList)
                qi.setWhere(whereList)
                qi.setAliasMap(aliasMap)
                qi.parseWhereClause(updateStatement.getWhere())
                querys.add(qi)

                System.out.println(qi)
            }
            else if (statement instanceof Delete) {
                Delete deleteStatement = (Delete) statement
                TableNameFinder tablesNamesFinder = new TableNameFinder()
                List<String> tableList = tablesNamesFinder.getTableList(deleteStatement)
                String whereList = tablesNamesFinder.getWhereList(deleteStatement)
                Map<String, String> aliasMap = tablesNamesFinder.getAliasMap()

                DeleteInfo qi = new DeleteInfo()
                qi.setqType(QueryInfo.QueryType.DELETE)
                qi.setTNames(tableList)
                qi.setWhere(whereList)
                qi.setAliasMap(aliasMap)
                qi.parseWhereClause(deleteStatement.getWhere())
                querys.add(qi)

                System.out.println(qi)
            }
            else if (statement instanceof CreateTable) {
                CreateTable createStatement = (CreateTable) statement
                TableNameFinder tablesNamesFinder = new TableNameFinder()
                ArrayList<ColDef> allColDef = tablesNamesFinder.getCreateInfo(createStatement)

                CreateTableInfo qi = new CreateTableInfo()
                String tableName = createStatement.getTable().getName().replace("`","").replace("\"", "")
                qi.setTableName(tableName)
                qi.setqType(QueryInfo.QueryType.CREATE)
                qi.setAllColDef(allColDef)
                qi.setConstraints(createStatement.getIndexes())
                qi.collectKey()
                qi.collectStatusColumn()
                if (!tables.containsKey(tableName)) {
                    tables.put(tableName, allColDef)
                    querys.add(qi)
                    System.out.println(qi)
                }
                else {
                    System.out.println("Table " + tableName + " already exists")
                }
            }
        } catch (JSQLParserException e) {
            System.out.println("Error in parsing the query: " + sql + "\n")
        }
    }

    static ArrayList<String> getTableColumns(String tableName) {
        ArrayList<String> ret = new ArrayList<String>()
        ArrayList<ColDef> cols = tables.get(tableName)
        if (cols == null) {
            return ret
        }
        for (ColDef col : cols) {
            ret.add(col.getColName())
        }
        return ret
    }

    static boolean isUniqueKey(String tableName, String columnName) {
        ArrayList<ColDef> cols = tables.get(tableName)
        if (cols == null) {
            return false
        }
        for (ColDef col : cols) {
            if (columnName.toUpperCase() == col.getColName().toUpperCase()) {
                return col.isUnique()
            }
        }
        return false
    }

    static boolean containColumn(String tableName, String columnName) {
        ArrayList<ColDef> cols = tables.get(tableName)
        if (cols == null) {
            return false
        }
        for (ColDef col : cols) {
            if (columnName.toUpperCase() == col.getColName().toUpperCase()) {
                return true
            }
        }
        return false
    }

    QueryProcessing() {

    }

}

