package net.sourceforge.pmd.lang.apex.rule.security.soqlInjection;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Track variables in a program scope.
 */
class VariableScope {
    private final Variable defaultReference;
	private final Map<String, Variable> variablesByName = new HashMap<String, Variable>();
	private final VariableScope parentScope;
	
	public VariableScope(VariableScope parent) {
	    this(parent, null);
	}
	
	/**
	 * @param parent the containing scope, or null for a new top level scope.
	 * @param defaultReference the default context for references, this for member functions or the
	 *        class' static context for static code.
	 */
	public VariableScope(VariableScope parent, Variable defaultReference) {
        this.defaultReference = defaultReference;
        if(defaultReference != null) {
            this.addVariable(defaultReference);
        }
		this.parentScope = parent;
	}
	
	public Variable getDefaultReference() {
	    if(defaultReference != null) return defaultReference;
	    if(parentScope != null) return parentScope.getDefaultReference();
	    // An error
	    return null;
	}
	
	/**
	 * Define a variable in this scope.
	 * @param variable the defined variable
	 */
	public void addVariable(Variable variable) {
	    variablesByName.put(variable.getLowerCaseName(), variable);
	}
	    
	/**
	 * Record a variable mutation that makes the variable unsafe. For example appending an
	 * untrusted string to a string variable as part of a string builder pattern.
	 * Parent scopes are searched to find the scope that owns the variable.
	 * 
	 * @param name name of the variable mutated
	 */
	public void markUnsafeVariableMutation(String name) {
	    Variable v = getVariable(name);
	    if(v != null) {
	        v.markUnsafeMutation();
		}
		// else is an Error condition. Can I log or warn?
	}
	
	/**
	 * Is the variable value safe for insertion into SOQL?
	 * Parent scopes are searched until the owning scope is found.
	 * 
	 * @param name name of the variable to check
	 * @return true if the variable is safe
	 */
	public boolean isVariableSafe(String name) {
	    Variable v = getVariable(name);
	    if(v != null) return v.isSafe();
		// An error condition. Can I log or warn?
		return false;
	}
	
	/**
	 * Return true if this scope has the given variable 
	 * @param name
	 * @return
	 */
	public boolean hasVariable(String name) {
	    return getVariable(name) != null;
	}

    public Variable getVariable(String name) {
        return getVariableByLowerCaseName(name.toLowerCase(Locale.ROOT));
    }
    
    private Variable getVariableByLowerCaseName(String lowerCaseName) {
        Variable v = variablesByName.get(lowerCaseName);
        if(v == null && parentScope != null) {
            v = parentScope.getVariableByLowerCaseName(lowerCaseName);
        }
        return v;
    }
}