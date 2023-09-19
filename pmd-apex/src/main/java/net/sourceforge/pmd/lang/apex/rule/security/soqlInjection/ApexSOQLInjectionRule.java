/**
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package net.sourceforge.pmd.lang.apex.rule.security.soqlInjection;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

import javax.naming.OperationNotSupportedException;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.apex.ast.ASTApexFile;
import net.sourceforge.pmd.lang.apex.ast.ASTAssignmentExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTBlockStatement;
import net.sourceforge.pmd.lang.apex.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTFieldDeclarationStatements;
import net.sourceforge.pmd.lang.apex.ast.ASTMethod;
import net.sourceforge.pmd.lang.apex.ast.ASTModifierNode;
import net.sourceforge.pmd.lang.apex.ast.ASTParameter;
import net.sourceforge.pmd.lang.apex.ast.ASTStandardCondition;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ApexNode;
import net.sourceforge.pmd.lang.apex.ast.ApexVisitor;
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
        String typeName = node.getSimpleName();
        System.out.println("--RJC MARKER--: validateClass(" + typeName + ")");
    	// Outer class static members are visible in the inner class.

        System.out.println("--RJC MARKER--: Static Fields:");
        Variable staticDefaultReference = new Variable(typeName, typeName);
        VariableScope classStaticVariableScope = new VariableScope(parentVariableScope, staticDefaultReference);
        node.getStaticFieldDeclarationStatements().forEach(registerFields(classStaticVariableScope));
        
        // Class static members are visible to non-static methods.
        System.out.println("--RJC MARKER--: Member Fields:");
        Variable memberDefaultReference = new Variable(typeName, "this");
        VariableScope classMemberVariableScope = new VariableScope(classStaticVariableScope, memberDefaultReference);
        node.getMemberFieldDeclarationStatements().forEach(registerFields(classMemberVariableScope));
        
        // Process methods in the class.
        node.children(ASTMethod.class).forEach((ASTMethod m) -> {
        	if(m.isSynthetic()) return;
        	VariableScope parentScope = m.isStatic() ? classStaticVariableScope : classMemberVariableScope;
            System.out.println("--RJC MARKER--: Method (" + m.getCanonicalName()+ ")");
        	validateMethod(m, parentScope, context);
        });
        
        // Process any inner classes. 
        node.getInnerClasses().forEach((ASTUserClass c) -> {
        	validateClass(c, classStaticVariableScope, context);
        });
        
        // TODO: If any of the above operations caused root scope variables to become unsafe due to mutation then
        // we would need to re-evaluate until mutation settles and this is no longer the case.
        // Currently mutable root scope variables are always marked unsafe so aBooleaning this issue.
    }
    
    /**
     * Create a Consumer that registers all of the fields in the given ASTFieldDeclarationStatements into the given VariableScope.
     * @param scope variable scope to register fields into
     * @return a Consumer of ASTFieldDeclarationStatements
     */
    private Consumer<ASTFieldDeclarationStatements> registerFields(VariableScope scope) {
        return (ASTFieldDeclarationStatements statements) -> {
            statements.children(ASTFieldDeclaration.class).forEach( (ASTFieldDeclaration field) -> {
                System.out.println("--RJC MARKER--: Field: (" + field.getName() + ")");
                Variable v = new Variable(statements.getTypeName(), field.getName(), isSafeFieldDeclaration(statements, field, scope));
                scope.addVariable(v);
            });
        };
    }
    
    /**
     * Check that a field declaration is initially safe. The field may become unsafe by later mutation.
     * @param f the field declaration to check
     * @param containingVariableScope the variable scope that contains the field.
     * @return true if the declaration is initially safe.
     */
    private boolean isSafeFieldDeclaration(ASTFieldDeclarationStatements statements, ASTFieldDeclaration field, VariableScope containingVariableScope) {
    	ASTModifierNode modifiers = statements.getModifiers();
    	
    	// It is unsafe if it is public, protected or global and is not final. These can be mutated externally.
    	if(!modifiers.isPrivate() && !modifiers.isFinal()) return false;
    	
		// Initially only final variables will be marked as safe, otherwise we'd have to look for possible
		// mutation in any method including methods that come after the database call.
		if(!modifiers.isFinal()) return false;
		
		// If it has an initial value then check for safety.
		// The initial value of a final member variable may be set in the constructor.
		// For now if we cannot find the initial value we will mark it unsafe.
		ApexNode<?> rValue = field.getInitialValueExpression();
		if(rValue != null) {
		    System.out.println("--RJC MARKER--: Has rValue");
    		ExpressionSafetyCheckVisitor visitor = new ExpressionSafetyCheckVisitor();
    		return rValue.acceptVisitor(visitor, containingVariableScope);
    	}
    
    	return false;
	}
    

	private void validateMethod(ASTMethod method, VariableScope parentScope, RuleContext context) {
    	VariableScope rootScope = new VariableScope(parentScope);
    	method.children(ASTParameter.class).forEach((ASTParameter p) -> {
    	    Variable parameterVariable = new Variable(p.getType(), p.getImage());
    	    rootScope.addVariable(parameterVariable);
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
//		throw new IllegalStateException("Code Not yet implemented");
    }
}
