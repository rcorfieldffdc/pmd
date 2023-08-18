/**
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package net.sourceforge.pmd.lang.apex.rule.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.naming.OperationNotSupportedException;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.apex.ast.ASTApexFile;
import net.sourceforge.pmd.lang.apex.ast.ASTAssignmentExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTBinaryExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTBlockStatement;
import net.sourceforge.pmd.lang.apex.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTFieldDeclarationStatements;
import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethod;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTModifierNode;
import net.sourceforge.pmd.lang.apex.ast.ASTParameter;
import net.sourceforge.pmd.lang.apex.ast.ASTStandardCondition;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ApexNode;
import net.sourceforge.pmd.lang.apex.ast.ApexVisitor;
import net.sourceforge.pmd.lang.apex.ast.ApexVisitorBase;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;

/**
 * Detects if variables in Database.query(variable) or Database.countQuery is escaped with
 * String.escapeSingleQuotes
 *
 * @author sergey.gorbaty
 *
 */
public class ApexSOQLInjectionRule extends AbstractApexRule{
	/** Variable types that cannot contain SOQL injection by their nature. For example an Integer has only numbers. */
    private static final Set<String> SAFE_VARIABLE_TYPES = 
        Stream.of(
            "double", "long", "decimal", "boolean", "id", "integer",
            "sobjecttype", "schema.sobjecttype", "sobjectfield", "schema.sobjectfield"
        ).collect(Collectors.toUnmodifiableSet());
    
    /** 
     * Identify a collection type and pick out the collection and what is contained as groups.
     * TODO: This is quite crude and will fail on nested collections. 
     */
    private static final Pattern COLLECTION_TYPE_REGEX = Pattern.compile("^(List|Set|Iterator)<([A-Z0-9_.]+)>$", Pattern.CASE_INSENSITIVE);
    
    /** 
     * The database methods that perform queries, all in lower case.
     * All of these methods take the query string as first argument. If this were to change then code would need to be updated.
     */
    private static final Set<String> DANGEROUS_DATABASE_METHODS = 
    	Stream.of("query", "querywithbinds", "countquery", "countquerywithbinds", "getquerylocator", "getquerylocatorwithbinds")
    	.collect(Collectors.toUnmodifiableSet());
    
    private static final String JOIN = "join";
    private static final String ESCAPE_SINGLE_QUOTES = "escapeSingleQuotes";
    private static final String STRING = "String";
    private static final String DATABASE = "Database";

    public ApexSOQLInjectionRule() {
        addRuleChainVisit(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
    	RuleContext context = asCtx(data);
    	
    	// Test classes are ignored. Inner classes will be processed by their parent.
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node) || node.isInnerClass()) {
            return data; // stops all the rules
        }
        
        validateClass(node, null, context);
        return context;
    }
    
    private void validateClass(ASTUserClass node, VariableScope parentVariableScope, RuleContext context) {  
    	// Outer class static members are visible in the inner class.
        VariableScope classStaticVariableScope = new VariableScope(parentVariableScope);
        node.getStaticFields().forEach((ASTFieldDeclarationStatements f) -> {
        	classStaticVariableScope.markVariableSafe(f.getFieldName(), isSafeFieldDeclaration(f, classStaticVariableScope));
        });
        
        // Class static members are visible to non-static methods.
        VariableScope classMemberVariableScope = new VariableScope(classStaticVariableScope);
        node.getMemberFields().forEach((ASTFieldDeclarationStatements f) -> {
        	classMemberVariableScope.markVariableSafe(f.getFieldName(), isSafeFieldDeclaration(f, classMemberVariableScope));
        });
        
        // Process methods in the class.
        node.children(ASTMethod.class).forEach((ASTMethod m) -> {
        	if(m.isSynthetic()) return;
        	VariableScope parentScope = m.isStatic() ? classStaticVariableScope : classMemberVariableScope;
        	validateMethod(m, parentScope, context);
        });
        
        // Process any inner classes. 
        node.getInnerClasses().forEach((ASTUserClass c) -> {
        	validateClass(c, classStaticVariableScope, context);
        });
        
        // TODO: If any of the above operations caused root scope variables to become unsafe due to mutation then
        // we would need to re-evaluate until mutation settles and this is no longer the case.
        // Currently mutable root scope variables are always marked unsafe so avoiding this issue.
    }
    
    /**
     * Check that a field declaration is initially safe. The field may become unsafe by later mutation.
     * @param f the field declaration to check
     * @param containingVariableScope the variable scope that contains the field.
     * @return true if the declaration is initially safe.
     */
    private boolean isSafeFieldDeclaration(ASTFieldDeclarationStatements f, VariableScope containingVariableScope) {
    	ASTModifierNode modifiers = f.getModifiers();
    	
    	// It is intrinsically safe if it is of a safe type
    	if(isSafeVariableType(f.getTypeName())) return true;

    	// It is unsafe if it is public, protected or global and is not final. These can be mutated externally.
    	if(!modifiers.isPrivate() && !modifiers.isFinal()) return false;
    	
		// Initially only final variables will be marked as safe, otherwise we'd have to look for possible
		// mutation in any method including methods that come after the database call.
		if(!modifiers.isFinal()) return false;
		
		// If it has an initial value then check for safety.
		// The initial value of a final member variable may be set in the constructor.
		// For now if we cannot find the initial value we will mark it unsafe.
		ApexNode<?> rValue = f.getInitialValueExpression();
		if(rValue != null) {
    		ExpressionSafetyCheckVisitor visitor = new ExpressionSafetyCheckVisitor();
    		rValue.acceptVisitor(visitor, containingVariableScope);
    		return visitor.isSafe();
    	}
    
    	return false;
	}
    
    /**
     * @param typeName the declared variable type, for example String, Integer, List&lt;Integer&gt;
     * @return true if this type cannot contain SOQL injection attacks. For example a number cannot contain non-numerics.
     */
    private boolean isSafeVariableType(String typeName) {
    	Matcher matcher = COLLECTION_TYPE_REGEX.matcher(typeName);
    	if(matcher.matches()) {
    		typeName = matcher.group(2);
    	}
        return SAFE_VARIABLE_TYPES.contains(typeName.toLowerCase(Locale.ROOT));
    }


	private void validateMethod(ASTMethod method, VariableScope parentScope, RuleContext context) {
    	VariableScope rootScope = new VariableScope(parentScope);
    	method.children(ASTParameter.class).forEach((ASTParameter p) -> {
    		rootScope.markVariableSafe(p.getImage(), isSafeVariableType(p.getType()));
    	});
    	
    	// There are 0 or 1 blocks depending on whether it is a coded method or synthetic
    	method.children(ASTBlockStatement.class).forEach((ASTBlockStatement b) -> {
        	validateBlockStatement(b, method, rootScope, context);    		
    	});
	}
	
	private void validateBlockStatement(ASTBlockStatement block, ASTMethod containingMethod, VariableScope containingScope, RuleContext context) {
		// Looking for variable declaration, variable assignment and Database method calls.
		// assignments and Database calls take Expressions which need to be validated using the Expression Visitor.
		
		// Original code reported the violations against the unsafe variable reference inside the Database.query call.
		// This behaviour should be preserved to help teams that have false positive databases/annotations.
		
		// FIXME
		throw new IllegalStateException("Code Not yet implemented");
    }

    private boolean isQueryMethodCall(ASTMethodCallExpression m) {
        return Helper.isMethodName(m, DATABASE, QUERY) || Helper.isMethodName(m, DATABASE, COUNT_QUERY);
    }


    /**
     * Track variables in a program scope.
     */
    private static class VariableScope {
    	private final Map<String, Boolean> isSafeByName = new HashMap<String, Boolean>();
    	private final VariableScope parentScope;
    	
    	/**
    	 * Construct a new top level scope.
    	 */
    	public VariableScope() {
    		this(null);
    	}
    	
    	/**
    	 * @param parent the containing scope, or null for a new top level scope.
    	 */
    	public VariableScope(VariableScope parent) {
    		this.parentScope = parent;
    	}
    	
    	/**
    	 * Set whether a variable is safe or unsafe in this scope.
    	 * This is called for a new variable defined in this scope.
    	 * @param name the variable name
    	 * @param isSafe is the declaration safe
    	 */
    	public void markVariableSafe(String name, boolean isSafe) {
    		isSafeByName.put(name,  isSafe);
    	}
    	
    	/**
    	 * Record a variable mutation that makes the variable unsafe. For example appending an
    	 * untrusted string to a string variable as part of a string builder pattern.
    	 * Parent scopes are searched to find the scope that owns the variable.
    	 * 
    	 * @param name name of the variable mutated
    	 */
    	public void markUnsafeVariableMutation(String name) {
    		if(isSafeByName.containsKey(name)) {
    			isSafeByName.put(name, false);
    		} else if (parentScope != null) {
    			parentScope.markUnsafeVariableMutation(name);
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
    		Boolean result = isSafeByName.get(name);
    		if(result != null) return result;
    		if(parentScope != null) return parentScope.isVariableSafe(name);
    		// An error condition. Can I log or warn?
    		return false;
    	}
    }
    
    /**
     * Visit an expression recursively looking for unsafe inputs that are not made safe.
     * Inputs are made safe by passing through String.escapeSingleQuotes()
     */
    private static class ExpressionSafetyCheckVisitor extends ApexVisitorBase<VariableScope, Void> {
    	private boolean safe = true;
    	    	
    	public boolean isSafe() {
    		return safe;
    	}
    	
    }
}
