class QueryInfo {

    enum QueryType {
        NONE, SELECT, INSERT, UPDATE, DELETE, CREATE
    }

    QueryType qType

    List<String> tablelist


    List<String> colNames
    String colName

    Map<String, String> aliasMap

    String where

    List<String> itemNames
    String itemName

    //this contains a mapping between colname -- var in the where clause
    Map<String, String> qColumnsVarMap


    ArrayList<String> qVars

    ArrayList<String> mapQvarsQuetsList


    QueryInfo() {
        this.qType = QueryType.NONE
        this.tablelist = new ArrayList<String>()
        this.colNames = new ArrayList<String>()
        this.qVars = new ArrayList<String>()
        this.mapQvarsQuetsList = new ArrayList<String>()
    }

    QueryInfo(QueryType qType, List<String> tableList, List<String> colNames) {
        this.qType = qType
        this.tablelist = tableList
        this.colNames = colNames
    }

    QueryInfo(QueryInfo q) {
        this(q.qType, q.tablelist, q.colNames)
        this.qVars = q.qVars
        this.mapQvarsQuetsList = q.mapQvarsQuetsList
        this.colName = q.colName
        this.itemName = q.itemName
        this.qColumnsVarMap = q.qColumnsVarMap
        this.where = q.where
    }

    QueryInfo(QueryInfo qInfo, ArrayList<String> qv) {
        this(qInfo)
        this.qVars = qv
    }

    QueryType getqType() {
        return qType
    }

    void setqType(QueryType qType) {
        this.qType = qType
    }

    List<String> getTNames() {
        return tablelist
    }

    void setTNames(List<String> tablelist) {
        this.tablelist = tablelist
    }

    List<String> getColNames() {
        return colNames
    }

    void setColNames(List<String> colList) {
        this.colNames = colList
    }

    //this function has the list of cols in one string e.g Select A,B,C
    void setColNames(String colList) {
        this.colName = colList
    }

    String getColName() {
        return this.colName
    }

    void setAliasMap(Map<String, String> aliasMap) {
        this.aliasMap = aliasMap
    }

    Map<String, String> getAliasMap() {
        return aliasMap
    }

    String getWhere() {
        return where
    }

    void setWhere(String whereList) {
        this.where = whereList
    }

    String getItemName() {
        return itemName
    }

    void setItemNames(List<String> itemList) {
        this.itemNames = itemList
    }

    void setItemNames(String itemList) {
        this.itemName = itemList
    }


    Map<String, String> getqColumnsVarMap() {
        return qColumnsVarMap
    }

    private void setqColumnsVarMap(Map<String, String> map) {
        if (this.qColumnsVarMap == null)
            this.qColumnsVarMap = new HashMap<String, String>()

        this.qColumnsVarMap.putAll(map)
    }

    @Override
    String toString() {
        return "QueryInfo [Type=" + qType + ", table Name(s)=" + tablelist + ", colNames=" + colNames + ", colName=" + colName + ", itemName=" + itemName + ", QueryVars=" + this.qVars + "]"
    }

    ArrayList<String> getMapQvarsQuetsList() {
        return this.mapQvarsQuetsList
    }

    void setMapQvarsQuetsList(ArrayList<String> mapQvarsQuetsList) {
        this.mapQvarsQuetsList = mapQvarsQuetsList
    }

    ArrayList<String> getqVars() {
        return this.qVars
    }

    void setqVars(ArrayList<String> qVars) {
        this.qVars = qVars
    }
}

