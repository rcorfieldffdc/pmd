/**
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package net.sourceforge.pmd.lang.java.ast;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import net.sourceforge.pmd.lang.ast.NodeStream;
import net.sourceforge.pmd.lang.java.ast.InternalInterfaces.AtLeastOneChildOfType;

/**
 * Common supertype for nodes that act as a kind of list of other nodes.
 * This is mainly provided as a way to share API and not a structural
 * distinction in the AST.
 *
 * <p>This node can be converted to a list with {@link #toList()}. Often these
 * nodes are optional in their parent, and so might be null. The method
 * {@link ASTList#orEmpty(ASTList) orEmpty} helps in such cases. For example
 * <pre>{@code
 * // This will throw NullPointerException if the class is not generic.
 * for (ASTTypeParameter tparam : classDecl.getTypeParameters()) {
 *
 * }
 * }</pre>
 *
 * Instead of explicitly checking for null, which is annoying, use the
 * following idiom:
 *
 * <pre>{@code
 * for (ASTTypeParameter tparam : ASTList.orEmpty(classDecl.getTypeParameters())) {
 *
 * }
 * }</pre>
 *
 *
 * <p>Note that though it is usually the case that the node lists all
 * its children, there is no guarantee about that. For instance,
 * {@link ASTFormalParameters} excludes the {@linkplain ASTReceiverParameter receiver parameter}.
 *
 * @param <N> Type of node contained within this list node
 */
public abstract class ASTList<N extends JavaNode> extends AbstractJavaNode implements Iterable<N> {

    private final Class<N> elementType;

    ASTList(int id, Class<N> kind) {
        super(id);
        this.elementType = kind;
    }

    /**
     * Returns the number of nodes in this list. This must be the number
     * of nodes yielded by the {@link #iterator()}.
     */
    public int size() {
        return getNumChildren();
    }

    /**
     * Returns a list containing the element of this node.
     */
    public List<N> toList() {
        return toStream().toList();
    }

    /**
     * Returns a node stream containing the same element this node contains.
     */
    public NodeStream<N> toStream() {
        return children(elementType);
    }

    @Override
    public Iterator<N> iterator() {
        return toStream().iterator();
    }

    /**
     * Returns an empty list if the parameter is null, otherwise returns
     * its {@link #toList()}.
     *
     * @param list List node
     * @param <N>  Type of elements
     *
     * @return A non-null list
     */
    public static <N extends JavaNode> @NonNull List<N> orEmpty(@Nullable ASTList<N> list) {
        return list == null ? Collections.emptyList() : list.toList();
    }

    /**
     * Super type for *nonempty* lists that *only* have nodes of type {@code <T>}
     * as a child.
     */
    static abstract class ASTNonEmptyList<T extends JavaNode> extends ASTList<T> implements AtLeastOneChildOfType<T> {

        ASTNonEmptyList(int id, Class<T> kind) {
            super(id, kind);
        }

        @Override
        @SuppressWarnings("unchecked")
        public T getChild(int index) {
            return (T) super.getChild(index);
        }
    }
}
