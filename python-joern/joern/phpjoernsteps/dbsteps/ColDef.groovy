class ColDef {
    String colName

    String colType
    ArrayList<String> colConstraints
    String tableName

    ArrayList<String> argumentsList; // for int(11) : it stores 11

    boolean isPrimaryKey = false

    boolean isUnique = false

    boolean isStatus = false

    boolean foreignKey = false

    ColDef() {
        this.colConstraints = new ArrayList<String>()
        this.argumentsList = new ArrayList<String>()
    }

    ColDef(String colName, String colType,
           ArrayList<String> colConstraints, String tableName) {

        this.colName = colName
        this.colType = colType
        this.colConstraints = colConstraints
        this.tableName = tableName
    }

    ColDef(String col, String tableName2) {
        this.tableName = tableName2
        col = col.trim()
        if (col.startsWith("(")) {
            int i = col.indexOf("(")
            col = col.substring(i + 1).trim()
        }


        this.colName = col.substring(0, col.indexOf(" ")).trim()

        col = col.substring(this.colName.length() + 1).trim()
        if (col.contains("(")) {
            this.colType = col.substring(0, col.indexOf("(")).trim()
        }
        else {
            this.colType = col.substring(0, col.indexOf(" ")).trim()
        }
        col = col.substring(colType.length()).trim()

        ArrayList<String> cCons = new ArrayList<String>()
        int size = col.length()
        for (int i = 0; i <= size; ) {
            if (col.indexOf(" ") != -1) { //end of line
                String temp = col.substring(0, col.indexOf(" ")).trim()

                if (temp.equalsIgnoreCase("NOT")) {
                    temp += " NULL"
                }
                else if (temp.equalsIgnoreCase("PRIMARY")) {
                    temp += " KEY"
                }
                col = col.substring(temp.length()).trim()
                cCons.add(temp)
                i = temp.length()
            }
            else {
                if (col.length() != 0 && !(col.endsWith(","))) {
                    cCons.add(col)
                }
                break
            }
        }
        this.colConstraints = cCons
    }

    @Override
    String toString() {
        return "ColDef [colName=" + colName + ", colType=" + colType + ", colConstraints=" + colConstraints + ", tableName="+ tableName + ", argumentsList=" + argumentsList + "]"
    }

    String getColName() {
        return colName
    }

    void setColName(String colName) {
        this.colName = colName
    }

    String getColType() {
        return colType
    }

    void setColType(String colType) {
        this.colType = colType
    }

    ArrayList<String> getColConstraints() {
        return colConstraints
    }

    void setColConstraints(ArrayList<String> colConstraints) {
        this.colConstraints = colConstraints
    }

    String getTableName() {
        return tableName
    }

    void setTableName(String tableName) {
        this.tableName = tableName
    }

    boolean isPrimaryKey() {
        return isPrimaryKey
    }

    void setPrimaryKey(boolean isPrimaryKey) {
        this.isPrimaryKey = isPrimaryKey
    }

    boolean isUnique() {
        return isUnique
    }

    void setUnique(boolean isUnique) {
        this.isUnique = isUnique
    }

    boolean isForeignKey() {
        return foreignKey
    }

    void setForeignKey(boolean foreignKey) {
        this.foreignKey = foreignKey
    }

    boolean isStatus() {
        return isStatus
    }

    void setStatus(boolean isStatus) {
        this.isStatus = isStatus
    }

    ArrayList<String> getArgumentsList() {
        return argumentsList
    }

    void setArgumentsList(ArrayList<String> argumentsStringList) {
        this.argumentsList = argumentsStringList
    }
}

