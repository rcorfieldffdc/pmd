/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package net.sourceforge.pmd.lang.apex.ast;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import apex.jorje.data.Identifier;
import apex.jorje.data.ast.TypeRef;
import apex.jorje.semantic.ast.compilation.UserClass;
import net.sourceforge.pmd.lang.ast.NodeStream;

/**
 * AST for a user class.
 * 
 * Examination of the result of ast-dump on a sample class has revealed the following:
 * 
 * <ul>
 *  <li>The first child is a {@link ASTModifierNode}, which provides class modifiers.
 *  <li>Then follow {@link ASTField} nodes which describe all static and non-static member fields.
 *  <li>Then follow {@link ASTFieldDeclarationStatements} which initialise the member fields.
 *  <li>Then follow the {@link ASTMethod} declarations. Static methods are marked as static in their
 *   modifiers. Constructors are similarly marked and have the name '&lt;init>'
 *  <li>The special Method '&lt;clinit>' is marked Synthetic and Static and initialises static members.
 *   This contains a list of {@link ASTFieldDeclarationStatements}
 * </ul>
 * 
 * This order is independent of order of the elements within the class. So a field that is defined
 * at the end of the class appears at the start with other fields.
 */
public final class ASTUserClass extends BaseApexClass<UserClass> implements ASTUserClassOrInterface<UserClass> {

    ASTUserClass(UserClass userClass) {
        super(userClass);
    }

    @Override
    protected <P, R> R acceptApexVisitor(ApexVisitor<? super P, ? extends R> visitor, P data) {
        return visitor.visit(this, data);
    }

    public String getSuperClassName() {
        return node.getDefiningType().getCodeUnitDetails().getSuperTypeRef().map(TypeRef::getNames)
            .map(it -> it.stream().map(Identifier::getValue).collect(Collectors.joining(".")))
            .orElse("");
    }

    public List<String> getInterfaceNames() {
        return node.getDefiningType().getCodeUnitDetails().getInterfaceTypeRefs().stream()
                .map(TypeRef::getNames).map(it -> it.stream().map(Identifier::getValue).collect(Collectors.joining(".")))
                .collect(Collectors.toList());
    }
    
    /**
     * @return true if this is an inner class.
     */
    public boolean isInnerClass() {
    	return !ancestors(ASTUserClass.class).isEmpty();
    }
    
    /**
     * @return inner classes of this class
     */
    public NodeStream<ASTUserClass> getInnerClasses() {
    	return children(ASTUserClass.class);
    }
    
    /**
     * @return fields defined in the class.
     * The member field's initialising {@link ASTFieldDeclarationStatements} are returned. 
     * From this it is possible to determine their modifiers and initial values.
     */
    public NodeStream<ASTFieldDeclarationStatements> getMemberFieldDeclarationStatements() {
    	return children(ASTFieldDeclarationStatements.class);
    }
    	
    /**
     * @return static fields defined in the class.
     * The static field's initialising {@link ASTFieldDeclarationStatements} are returned. 
     * From this it is possible to determine their modifiers and initial values.
     */
    public NodeStream<ASTFieldDeclarationStatements> getStaticFieldDeclarationStatements() {
    	return children(ASTMethod.class)
    		.filter((ASTMethod m) -> m.isSynthetic() && m.getImage().equals("<clinit>"))
    		.flatMap((ASTMethod m) -> m.children(ASTFieldDeclarationStatements.class));
    }
}
