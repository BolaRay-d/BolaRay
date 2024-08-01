class SelectInfo extends WhereInfo{

    List<Map.Entry<String, String>> selectItemList
    SelectInfo() {
        super()
        selectItemList = new ArrayList<>()
    }

    SelectInfo(SelectInfo selectInfo) {
        super(selectInfo)
        selectItemList = selectInfo.selectItemList
    }

    @Override
    String toString() {
        return "SelectInfo {" + " tablelist : " + tablelist + " selectItemList : " + selectItemList.toString().replace("=", ".") + " conditionCols : " + conditionCols + " conditionOps : " + conditionOps + " conditionVals : " + conditionVals + " }"
    }

    void setSelectItemList(List<Map.Entry<String, String>> selectItemList) {
        this.selectItemList = selectItemList
    }

    List<Map.Entry<String, String>> getSelectItemList() {
        return selectItemList
    }

    void setConditionMap(Map<String, String> conditionMap) {
        for (Map.Entry<String, String> entry : conditionMap.entrySet()) {
            conditionCols.add(entry.getKey())
            conditionOps.add("=")
            conditionVals.add(entry.getValue())
        }
    }

}