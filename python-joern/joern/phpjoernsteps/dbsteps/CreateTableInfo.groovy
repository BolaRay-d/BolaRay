import net.sf.jsqlparser.statement.create.table.ForeignKeyIndex
import net.sf.jsqlparser.statement.create.table.Index

class CreateTableInfo extends QueryInfo{
    ArrayList<ColDef> allColDef
    ArrayList<Index> constraints
    ArrayList<String> statusCols

    String primaryKey

    String tableName

    ArrayList<String> foreignKeys

    ArrayList<String> uniqueKeys

    boolean isUserTable

    ArrayList<String> statusColTypes

    CreateTableInfo() {
        super()
        this.allColDef = new ArrayList<ColDef>()
        this.constraints = new ArrayList<Index>()
        this.statusCols = new ArrayList<String>()
        this.primaryKey = new String()
        this.tableName = new String()
        this.foreignKeys = new ArrayList<String>()
        this.uniqueKeys = new ArrayList<String>()
        this.isUserTable = false
        this.statusColTypes = new ArrayList<String>()
        statusColTypes.add("INT[1]")
        statusColTypes.add("TINYINT[1]")
        statusColTypes.add("CHAR[1]")
        statusColTypes.add("BOOLEAN")
        statusColTypes.add("BOOL")
        statusColTypes.add("ENUM")
    }

    CreateTableInfo(CreateTableInfo createTableInfo) {
        super(createTableInfo)
        this.allColDef = createTableInfo.allColDef
        this.constraints = createTableInfo.constraints
        this.statusCols = createTableInfo.statusCols
        this.primaryKey = createTableInfo.primaryKey
        this.tableName = createTableInfo.tableName
        this.foreignKeys = createTableInfo.foreignKeys
        this.uniqueKeys = createTableInfo.uniqueKeys
        this.isUserTable = createTableInfo.isUserTable
        this.statusColTypes = createTableInfo.statusColTypes
    }

    ArrayList<ColDef> getAllColDef() {
        return allColDef
    }


    void setAllColDef(ArrayList<ColDef> allColDef) {
        this.allColDef = allColDef
    }

    ArrayList<Index> getConstraints() {
        return constraints
    }

    void setConstraints(ArrayList<Index> constraints) {
        this.constraints = constraints
    }

    ArrayList<String> getStatusCols() {
        return statusCols
    }

    void setStatusCols(ArrayList<String> statusCols) {
        this.statusCols = statusCols
    }

    String getPrimaryKey() {
        return primaryKey
    }

    String getTableName() {
        return tableName
    }

    void setTableName(String tableName) {
        this.tableName = tableName
    }

    ArrayList<String> getForeignKeys() {
        return foreignKeys
    }

    ArrayList<String> getUniqueKeys() {
        return uniqueKeys
    }

    boolean isUserTable() {
        return isUserTable
    }

    void collectStatusColumn() {
        ArrayList<String> statusCols = new ArrayList<String>()
        for (ColDef col : this.allColDef) {
            String colName = col.getColName()
            for (String statusColType : statusColTypes ) {
                if (col.getColType().toUpperCase().contains(statusColType)) {
                    col.setStatus(true)
                    statusCols.add(colName)
                    break
                }
            }
            if (colName.toUpperCase().contains("STATUS")) {
                col.setStatus(true)
                statusCols.add(colName)
            }
            if (colName.toUpperCase().contains("PASSWD") || colName.toUpperCase().contains("PASSWORD") || colName.toUpperCase().contains("PASS") || colName.toUpperCase().contains("PW")) {
                isUserTable = true
            }
        }
        setStatusCols(statusCols)
    }

    void collectKey() {
        if (this.constraints) {
            for (Index index : this.constraints) {
                if (index.getType().equals("PRIMARY KEY")) {
                    String key = ""
                    for (String col : index.getColumnsNames()) {
                        key += col.replace("`", "") + ","
                    }
                    key = key.substring(0, key.length() - 1)
                    this.primaryKey = key
                    for (ColDef col : this.allColDef) {
                        if (col.getColName().equals(key)) {
                            col.setPrimaryKey(true)
                        }
                    }
                }
                else if (index.getType().equals("UNIQUE KEY")) {
                    for (String col : index.getColumnsNames()) {
                        this.uniqueKeys.add(col.replace("`", ""))
                    }
                    for (ColDef col : this.allColDef) {
                        if (this.uniqueKeys.contains(col.getColName())) {
                            col.setUnique(true)
                        }
                    }
                }
                else if (index.getType().equals("FOREIGN KEY")) {
                    ForeignKeyIndex foreignKeyIndex = (ForeignKeyIndex) index
                    for (int i = 0; i < foreignKeyIndex.getColumnsNames().size(); ++i) {
                        String col = foreignKeyIndex.getColumnsNames().get(i)
                        this.foreignKeys.add(col.replace("`", ""))
                        String table = this.tableName
                        String refTable = foreignKeyIndex.getTable().getName()
                        if (i < foreignKeyIndex.getReferencedColumnNames().size()) {
                            String refCol = foreignKeyIndex.getReferencedColumnNames().get(i)
                            if (QueryProcessing.tableRelations.get(table + "." + col) == null) {
                                QueryProcessing.tableRelations.put(table + "." + col, new HashSet<String>())
                            }
                            QueryProcessing.tableRelations.get(table + "." + col).add(refTable + "." + refCol)
                            if (QueryProcessing.tableRelations.get(refTable + "." + refCol) == null) {
                                QueryProcessing.tableRelations.put(refTable + "." + refCol, new HashSet<String>())
                            }
                            QueryProcessing.tableRelations.get(refTable + "." + refCol).add(table + "." + col)
                            System.out.println(table + "." + col + " = " + refTable + "." + refCol)
                        }
                    }
                    for (ColDef col : this.allColDef) {
                        if (this.foreignKeys.contains(col.getColName())) {
                            col.setForeignKey(true)
                        }
                    }
                }
            }
        }
        for (ColDef col : this.allColDef) {
            if (col.getColConstraints()) {
                ArrayList<String> colConstraints = col.getColConstraints()
                for (int i = 0; i < colConstraints.size(); ++i) {
                    String constraint = colConstraints.get(i)
                    if (constraint.toUpperCase().equals("PRIMARY")) {
                        this.primaryKey = col.getColName()
                        col.setPrimaryKey(true)
                    }
                    else if (constraint.toUpperCase().equals("UNIQUE")) {
                        this.uniqueKeys.add(col.getColName())
                        col.setUnique(true)
                    }
                    else if (constraint.toUpperCase().equals("FOREIGN")) {
                        this.foreignKeys.add(col.getColName())
                        col.setForeignKey(true)
                    }
                }
            }
        }
        if (this.primaryKey == "") {
            this.primaryKey = this.allColDef.get(0).getColName()
            this.allColDef.get(0).setPrimaryKey(true)
        }
    }

    @Override
    String toString() {
        return "CreateTableInfo {" +
                " tableName : " + tableName +
                " statusCols : " + statusCols +
                " primaryKey : " + primaryKey +
                " foreignKeys : " + foreignKeys +
                " uniqueKeys : " + uniqueKeys +
                " isUserTable : " + isUserTable +
                " }"
    }
}

