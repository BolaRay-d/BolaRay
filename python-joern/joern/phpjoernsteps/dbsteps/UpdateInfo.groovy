class UpdateInfo extends WhereInfo{

    UpdateInfo() {
        super();
    }

    UpdateInfo(UpdateInfo updateInfo) {
        super(updateInfo);
    }

    @Override
    String toString() {
        return "UpdateInfo {" + " table : " + tablelist + " colNames : " + colNames + " itemNames : " + itemNames + " conditionCols : " + conditionCols + " conditionOps : " + conditionOps + " conditionVals : " + conditionVals + " } ";
    }
}
