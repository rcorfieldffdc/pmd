/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package net.sourceforge.pmd.lang.apex.ast;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

class ASTMethodTest extends ApexParserTestBase {

    @Test
    void testConstructorName() {
        ASTUserClass node = (ASTUserClass) parse("public class Foo { public Foo() {} public void bar() {} }");
        List<ASTMethod> methods = node.children(ASTMethod.class).toList();
        assertEquals("Foo", methods.get(0).getImage()); // constructor
        assertEquals("<init>", methods.get(0).getCanonicalName());
        assertEquals("bar", methods.get(1).getImage()); // normal method
    }
    
    @Test
    void testIsStaticGivenStaticMethodReturnsTrue() {
    	ASTUserClass cls = (ASTUserClass) parse("public class Foo { public static void bar() {} }");
    	ASTMethod method = cls.children(ASTMethod.class).first();
    	assertEquals(method.isStatic(), true);
    }
    
    @Test
    void testIsStaticGivenMemberMethodReturnsFalse() {
    	ASTUserClass cls = (ASTUserClass) parse("public class Foo { public void bar() {} }");
    	ASTMethod method = cls.children(ASTMethod.class).first();
    	assertEquals(method.isStatic(), false);
    }

    @Test
    void testIsStaticGivenStaticInitialiserReturnsTrue() {
    	ASTUserClass cls = (ASTUserClass) parse("public class Foo { static {} }");
    	ASTMethod method = cls.children(ASTMethod.class).first();
    	assertEquals(method.isStatic(), true);
    }
}
