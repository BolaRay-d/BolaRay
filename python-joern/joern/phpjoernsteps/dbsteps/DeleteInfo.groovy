class DeleteInfo extends WhereInfo{

    DeleteInfo() {
        super();
    }

    DeleteInfo(DeleteInfo deleteInfo) {
        super(deleteInfo);
    }

    @Override
    String toString() {
        return "DeleteInfo {" + " table : " + tablelist + " conditionCols : " + conditionCols + " conditionOps : " + conditionOps + " conditionVals : " + conditionVals + " }";
    }
}
