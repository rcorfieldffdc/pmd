/**
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package net.sourceforge.pmd.lang.apex.ast;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import net.sourceforge.pmd.lang.ast.NodeStream;

class ASTUserClassTest extends ApexParserTestBase {

    @Test
    void testClassName() {
        ASTUserClass node = (ASTUserClass) parse("class Foo { }");
        assertEquals("Foo", node.getSimpleName());
    }

    @Test
    void testInnerClassName() {
        ASTUserClass foo = (ASTUserClass) parse("class Foo { class Bar { } }");
        ASTUserClass innerNode = foo.descendants(ASTUserClass.class).firstOrThrow();
        assertEquals("Bar", innerNode.getSimpleName());
    }

    @Test
    void testSuperClassName() {
        ASTUserClass toplevel = (ASTUserClass) parse("public class AccountTriggerHandler extends TriggerHandler {}");
        assertEquals("TriggerHandler", toplevel.getSuperClassName());
    }

    @Test
    void testSuperClassName2() {
        ASTUserClass toplevel = (ASTUserClass) parse("public class AccountTriggerHandler extends Other.TriggerHandler {}");
        assertEquals("Other.TriggerHandler", toplevel.getSuperClassName());
    }

    @Test
    void testInterfaces() {
        ASTUserClass toplevel = (ASTUserClass) parse("public class AccountTriggerHandler implements TriggerHandler, Other.Interface2 {}");
        assertEquals(Arrays.asList("TriggerHandler", "Other.Interface2"), toplevel.getInterfaceNames());
    }
    
    @Test
    void testGetInnerClasses() {
    	ASTUserClass topLevel = (ASTUserClass) parse("public class OuterClass { public class InnerClass {} }");
    	List<ASTUserClass> innerClasses = topLevel.getInnerClasses().toList();
    	assertEquals(1, innerClasses.size());
    	assertEquals("InnerClass", innerClasses.get(0).getImage());
    }
    
    @Test
    void testIsInnerClass() {
    	ASTUserClass topLevel = (ASTUserClass) parse("public class OuterClass { public class InnerClass {} }");
    	assertEquals(false, topLevel.isInnerClass());
    	List<ASTUserClass> innerClasses = topLevel.getInnerClasses().toList();
    	assertEquals(true, innerClasses.get(0).isInnerClass());
    }

    @Test
    void testGetMemberFields() {
    	ASTUserClass topLevel = (ASTUserClass) parse("public class OuterClass { private Integer foo; public Integer bar = 10; private static integer A_CONSTANT = 0;}");
    	NodeStream<ASTFieldDeclarationStatements> members = topLevel.getMemberFields();
    	assertEquals(2, members.count());
    	
    	Object[] expectedNames = {"bar","foo"};
    	Object[] foundNames = members.toStream().map((ASTFieldDeclarationStatements x) -> x.getFieldName()).collect(Collectors.toList()).toArray();
    	Arrays.sort(foundNames);
    	
    	assertArrayEquals(expectedNames, foundNames);
    }
    
    @Test
    void testGetStaticFields() {
    	ASTUserClass topLevel = (ASTUserClass) parse("public class OuterClass { private Integer foo; public static Integer bar = 10; private static final integer A_CONSTANT = 0;}");
    	NodeStream<ASTFieldDeclarationStatements> members = topLevel.getStaticFields();
    	assertEquals(2, members.count());
    	
    	Object[] expectedNames = {"A_CONSTANT","bar"};
    	Object[] foundNames = members.toStream().map((ASTFieldDeclarationStatements x) -> x.getFieldName()).collect(Collectors.toList()).toArray();
    	Arrays.sort(foundNames);
    	
    	assertArrayEquals(expectedNames, foundNames);    	
    }
}
