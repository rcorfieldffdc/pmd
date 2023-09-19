package net.sourceforge.pmd.lang.apex.rule.security.soqlInjection;

import net.sourceforge.pmd.lang.apex.ast.ASTBinaryExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTClassRefExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTField;
import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTReferenceExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTSuperMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTThisMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTThisVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ApexNode;
import net.sourceforge.pmd.lang.apex.ast.ApexVisitorBase;
import net.sourceforge.pmd.lang.ast.Node;
import net.sourceforge.pmd.lang.ast.NodeStream;

/**
 * Visit an expression recursively looking for unsafe inputs that are not made safe.
 * Inputs are made safe by passing through String.escapeSingleQuotes().
 * Passing through an external function makes information unsafe unless we know the function to
 * be safe. For example String.join() does not change the safety of its argument, but
 * MyQueryBuilderClass.buildSearchQuery() is unknown so unsafe.
 */
class ExpressionSafetyCheckVisitor extends ApexVisitorBase<VariableScope, Boolean> {
	private int indent = 0;
	
	    	
	private void logEntry(String text) {
	    log(text);
	    indent++;
	}
	
	private void log(String text) {
        for(int i = 0; i < indent; i++) System.out.print("|--");
        System.out.println(text);	    
	}
	
	private void logExit() {
	    indent--;
	}
	
	@Override
    protected Boolean visitChildren(Node node, VariableScope data) {
	    boolean isSafe = true;
        // this explicit loop is faster than iterating on a children node stream.
        for (int i = 0, numChildren = node.getNumChildren(); i < numChildren; i++) {
            Boolean childResult = node.getChild(i).acceptVisitor(this, data);
            if(childResult != null) isSafe &= childResult;
        }
        return isSafe;
    }
	
    @Override
    public Boolean visit(ASTBinaryExpression node, VariableScope data) {
        // TODO Auto-generated method stub
        logEntry("ASTBinaryExpression: " + node.getOp());
        try {
            return super.visit(node, data);
        } finally {
            logExit();
        }
    }

    @Override
    public Boolean visit(ASTLiteralExpression node, VariableScope data) {
        // TODO Auto-generated method stub
        logEntry("ASTLiteralExpression: " + node.getImage());
        try {
            return super.visit(node, data);
        } finally {
            logExit();
        }
    }

    @Override
    public Boolean visit(ASTClassRefExpression node, VariableScope data) {
        // TODO Auto-generated method stub
        logEntry("ASTClassRefExpression: " + node.getImage());
        try {
            return super.visit(node, data);
        } finally {
            logExit();
        }
    }

    @Override
    public Boolean visit(ASTField node, VariableScope data) {
        // TODO Auto-generated method stub
        logEntry("ASTField: " + node.getImage());
        try {
            return super.visit(node, data);
        } finally {
            logExit();
        }
    }

    @Override
    public Boolean visit(ASTMethodCallExpression node, final VariableScope currentScope) {
        try {

            // The name as presented an own method call could be "myMethod". A static call "FooClass.myMethod". A member call "someString.toLowerCase"
            // The this variable, if present, is removed. TODO: Check this holds where member variables are masked when validating inside a method.
            String fullName = node.getFullMethodName();
            // The name of the method being called. Example "toLowerCase"
            String name = node.getMethodName();
            // The referenceName is null for an implicit own method, the class name for an explicit static method call, another class name for an
            // explicit static method call to another class, or a variable name.
            String referenceName = node.getReferenceName();
            
            String definingType = null;
            
            // Is the reference a variable? If so then look at its type to work out the defining class.
            if(referenceName == null) {
                definingType = currentScope.getDefaultReference().getTypeName();
            } else if (currentScope.hasVariable(referenceName)){
                Variable v = currentScope.getVariable(referenceName);
                if(v != null) definingType = v.getTypeName();
            } else {
                definingType = referenceName;
            }
            
            // The first child is the reference to wherever the method is defined. It's an EmptyReference for a self method
            // Subsequent children are the parameters.
            MethodBehaviour behaviour = MethodBehaviour.getBehaviour(definingType, name);
            logEntry("ASTMethodCallExpression: fullName=" + fullName + ", name=" + name + ", reference=" + referenceName + " /definingType=" + definingType + " /behaviour=" + behaviour.name());
            return behaviour.visit(node, currentScope, new MethodBehaviour.Callback() {
                
                @Override
                public void registerViolation(ApexNode<?> violatingNode) {
                    // TODO Auto-generated method stub
                    log("VIOLATION " + violatingNode.getImage());
                }
                
                @Override
                public boolean areSafe(NodeStream<ApexNode<?>> relevantInputs) {
                    boolean isSafe = true;
                    // this explicit loop is faster than iterating on a children node stream.
                    // copied from visitChildren implementation.
                    for (int i = 0, numChildren = relevantInputs.count(); i < numChildren; i++) {
                        Boolean childResult = node.getChild(i).acceptVisitor(ExpressionSafetyCheckVisitor.this, currentScope);
                        if(childResult != null) isSafe &= childResult;
                    }
                    return isSafe;
                }
            });
        } finally {
            logExit();
        }
    }
    
    @Override
    public Boolean visit(ASTReferenceExpression node, VariableScope data) {
        // TODO Auto-generated method stub
        logEntry("ASTReferenceExpression: " + node.getImage());
        try {
            return super.visit(node, data);
        } finally {
            logExit();
        }
    }

    @Override
    public Boolean visit(ASTSuperMethodCallExpression node, VariableScope data) {
        // TODO Auto-generated method stub
        logEntry("ASTSuperMethodCallExpression: " + node.getImage());
        try {
            return super.visit(node, data);
        } finally {
            logExit();
        }
    }

    @Override
    public Boolean visit(ASTThisMethodCallExpression node, VariableScope data) {
        // TODO Auto-generated method stub
        logEntry("ASTThisMethodCallExpression: " + node.getImage());
        try {
            return super.visit(node, data);
        } finally {
            logExit();
        }
    }

    @Override
    public Boolean visit(ASTThisVariableExpression node, VariableScope data) {
        // TODO Auto-generated method stub
        logEntry("ASTThisVariableExpression: " + node.getImage());
        try {
            return super.visit(node, data);
        } finally {
            logExit();
        }
    }

    @Override
    public Boolean visit(ASTVariableExpression node, VariableScope data) {
        // TODO Auto-generated method stub
        
        // This represents a variable reference.
        // If it's local it has an EmptyReferenceExpression
        // If it's in another class (or maybe this one by name) it has a ReferenceExpression
        // Need to see what happens with public member variables on instances held by variables?
        
        logEntry("ASTVariableExpression: " + node.getImage());
        try {
            return super.visit(node, data);
        } finally {
            logExit();
        }
    }    	
}