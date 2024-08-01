package udg.php.useDefAnalysis.environments;

import udg.ASTProvider;
import udg.useDefAnalysis.environments.EmitDefAndUseEnvironment;
import udg.useDefGraph.UseOrDef;

import java.util.Collection;
import java.util.LinkedList;

public class ArgumentListEnvironment extends EmitDefAndUseEnvironment {

    private boolean isCompact;
    public ArgumentListEnvironment(boolean isCompact) {
        super();
        this.isCompact = isCompact;
    }
    @Override
    public boolean isDef(ASTProvider child) {
        return false;
    }

    @Override
    public boolean isUse(ASTProvider child) {
        return false;
    }

    @Override
    public boolean isCompact() {
        return this.isCompact;
    }

    @Override
    public void addChildSymbols(LinkedList<String> childSymbols,
                                ASTProvider child) {
        if (isCompact) {
            this.symbols.add("1");
            this.symbols.add(child.getEscapedCodeStr());
            this.symbols.add("-1");
        }
        else {
            int childNum = child.getChildNumber();
            this.symbols.add(Integer.toString(childNum));
            this.symbols.addAll(childSymbols);
            this.symbols.add("-1");
        }
    }

//    @Override
//    public Collection<UseOrDef>  useOrDefsFromSymbols(ASTProvider child) {
//        return this.emptyUseOrDef;
//    }

    @Override
    public LinkedList<String> upstreamSymbols() {
        return this.symbols;
    }
}
