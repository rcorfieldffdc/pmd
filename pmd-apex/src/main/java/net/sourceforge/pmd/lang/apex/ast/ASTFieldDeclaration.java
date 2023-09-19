/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package net.sourceforge.pmd.lang.apex.ast;

import apex.jorje.semantic.ast.statement.FieldDeclaration;

public final class ASTFieldDeclaration extends AbstractApexNode<FieldDeclaration> {

    ASTFieldDeclaration(FieldDeclaration fieldDeclaration) {
        super(fieldDeclaration);
    }


    @Override
    protected <P, R> R acceptApexVisitor(ApexVisitor<? super P, ? extends R> visitor, P data) {
        return visitor.visit(this, data);
    }

    @Override
    public String getImage() {
        return getName();
    }
    
    /**
     * Return the expression that gives the initial value, or null if no initial value is provided.
     * @return an Expression of some kind, for example {@link ASTBinaryExpression} or {@link ASTLiteralExpression}, or null
     */
    public ApexNode<?> getInitialValueExpression() {
        return this.getNumChildren() == 2 ? getFirstChild() : null;
    }

    public String getName() {
        if (node.getFieldInfo() != null) {
            return node.getFieldInfo().getName();
        }
        ASTVariableExpression variable = getFirstChildOfType(ASTVariableExpression.class);
        if (variable != null) {
            return variable.getImage();
        }
        return null;
    }
}
