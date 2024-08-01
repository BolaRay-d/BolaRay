package udg.php.useDefAnalysis.environments;

import udg.ASTProvider;
import udg.useDefAnalysis.environments.EmitDefAndUseEnvironment;
import udg.useDefGraph.UseOrDef;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;

public class CallExpressionBaseEnvironment extends EmitDefAndUseEnvironment {

    HashSet<Integer> defArguments = new HashSet<Integer>();

    boolean isCompact = false;

    public void setDefArguments(ASTProvider child) {
        String name = "";
        if (child.getTypeAsString().equals("Identifier")) {
            name = child.getChild(0).getEscapedCodeStr();
        }
        if (name.equals("array_push")) {
            defArguments.add(0);
        }
        if (name.equals("compact")) {
            isCompact = true;
        }
    }

    @Override
    public boolean isDef(ASTProvider child) {
        int childNum = child.getChildNumber();
        if (childNum == 1) {
            return true;
        }
        return false;
    }

    @Override
    public boolean isUse(ASTProvider child) {
        return false;
    }

    @Override
    public boolean isCompact()
    {
        return isCompact;
    }

    public void addChildSymbols(LinkedList<String> childSymbols,
                                ASTProvider child) {
        this.useSymbols.addAll(childSymbols);
        if (isDef(child)) {
            boolean isDefArgument = false;
            for (int i = 0; i < childSymbols.size(); i++) {
                try {
                    int index = Integer.parseInt(childSymbols.get(i));
                    if (defArguments.contains(index)) {
                        isDefArgument = true;
                    }
                    if (index == -1) {
                        isDefArgument = false;
                    }
                } catch (NumberFormatException e){
                    if (isDefArgument) {
                        defSymbols.add(childSymbols.get(i));
                    }
                }
            }
        }
    }

    @Override
    public Collection<UseOrDef> useOrDefsFromSymbols(ASTProvider child)
    {
        LinkedList<UseOrDef> retval = createUsesForAllSymbols(useSymbols);
        if (isDef(child)) {
            retval.addAll(createDefsForAllSymbols(defSymbols));
        }
        return retval;
    }
}
