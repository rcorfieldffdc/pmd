package net.sourceforge.pmd.lang.apex.rule.security.soqlInjection;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ApexNode;
import net.sourceforge.pmd.lang.ast.NodeStream;


enum MethodBehaviour {
    /** The output of this method is always safe, regardless of its input. */
    OUTPUT_IS_SAFE {
        @Override
        public boolean visit(ASTMethodCallExpression node, VariableScope scope, Callback callback) {
            return true;
        }
    },
    
    /** The output of this method is always unsafe, regardless of its input. */
    OUTPUT_IS_UNSAFE {
        @Override
        public boolean visit(ASTMethodCallExpression node, VariableScope scope, Callback callback) {
            return false;
        }
    },
    
    /** The output of this method is safe only if its input is safe. */
    OUTPUT_SAFETY_REFLECTS_INPUT {
        @Override
        public boolean visit(ASTMethodCallExpression node, VariableScope scope, Callback callback) {
            // Process all children including the first which is the variable on which this method is referenced.
            return callback.areSafe(node.children());
        }
    },
    
    /** 
     * This method constitutes a SOQL Injection vulnerability if its first parameter is unsafe.
     * Subsequent parameters include bind maps and access levels. 
     * The output of all of these functions is unsafe, because they contain user data from the database (Stored Injection Attack)
     */
    DATABASE_QUERY {
        @Override
        public boolean visit(ASTMethodCallExpression node, VariableScope scope, Callback callback) {
            // The first parameter is the query string.
            // The first child of the node is the Database class itself. Subsequent children are the parameters.
            boolean isInjection = callback.areSafe(node.children().drop(1).take(1));
            if(isInjection) callback.registerViolation(node);
            
            // The results of a query are always unsafe
            return false;
        }        
    };
    
    public interface Callback {
        boolean areSafe(NodeStream<ApexNode<?>> relevantInputs);
        void registerViolation(ApexNode<?> violatingNode);
    }
    
    public abstract boolean visit(ASTMethodCallExpression node, VariableScope scope, Callback callback);
    
    /**
     * Derive the method behaviour given a full method reference. This is assumed to be a static method.
     * @param reference the type owning the reference, for example String or MyClass
     * @param name the method name
     * @return the behaviour of this method.
     */
    public static MethodBehaviour getBehaviour(String reference, String name) {
        String referenceLower = reference.toLowerCase(Locale.ROOT);
        String nameLower = name.toLowerCase(Locale.ROOT);
        MethodBehaviour result = KNOWN_METHOD_BEHAVIOURS.get(referenceLower + '.' + nameLower);
        if(result == null) result = KNOWN_METHOD_BEHAVIOURS.get(referenceLower + ".*");
        if(result == null) result = MethodBehaviour.OUTPUT_IS_UNSAFE; // Unrecognised methods cannot be trusted.
        return result;
    }
    
    /** 
     * The database methods that perform queries, all in lower case.
     * All of these methods take the query string as first argument. 
     */
    private static final String[] DATABASE_QUERY_METHODS = {"query", "querywithbinds", "countquery", "countquerywithbinds", "getquerylocator", "getquerylocatorwithbinds"};
    
    private static final Map<String, MethodBehaviour> KNOWN_METHOD_BEHAVIOURS;
    static {
        Map<String, MethodBehaviour> tmp = new HashMap<String, MethodBehaviour>();
        tmp.put("string.escapesinglequotes", MethodBehaviour.OUTPUT_IS_SAFE);
        tmp.put("string.*", MethodBehaviour.OUTPUT_SAFETY_REFLECTS_INPUT);
        for(String dangerousMethod : DATABASE_QUERY_METHODS) {
            tmp.put("database." + dangerousMethod, MethodBehaviour.DATABASE_QUERY);
        }
        KNOWN_METHOD_BEHAVIOURS = Collections.unmodifiableMap(tmp);
    }

}
