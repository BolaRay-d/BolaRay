class InsertInfo extends QueryInfo {

    InsertInfo() {
        super()
    }

    InsertInfo(InsertInfo insertTableInfo) {
        super(insertTableInfo)
    }

    @Override
    String toString() {
        return "InsertInfo {" + " table : " + tablelist + " colNames : " + colNames + " itemNames : " + itemNames + " }"
    }
}

