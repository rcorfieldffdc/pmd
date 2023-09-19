package net.sourceforge.pmd.lang.apex.rule.security.soqlInjection;

import java.util.Collections;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Represent a variable in code.
 */
class Variable {
    /** Variable types that cannot contain SOQL injection by their nature. For example an Integer has only numbers. */
    private static final Set<String> SAFE_VARIABLE_TYPES = 
            Collections.unmodifiableSet(Stream.of(
                "double", "long", "decimal", "boolean", "id", "integer",
                "sobjecttype", "schema.sobjecttype", "sobjectfield", "schema.sobjectfield",
                "accesslevel", "system.accesslevel"
            ).collect(Collectors.toSet()));
    

    /** 
     * Identify a collection type and pick out the collection and what is contained as groups.
     * TODO: This is quite crude and will fail on nested collections. 
     */
    private static final Pattern COLLECTION_TYPE_REGEX = Pattern.compile("^(List|Set|Iterator)<([A-Z0-9_.]+)>$", Pattern.CASE_INSENSITIVE);

    private final String typeName;
    private final String lowerCaseName;
    private final boolean intrinsicallySafe;
    private boolean safe;
    
    public Variable(String typeName, String name) {
        this.typeName = typeName;
        this.intrinsicallySafe = this.safe = isSafeVariableType(typeName);
        this.lowerCaseName = name.toLowerCase(Locale.ROOT);
    }
    
    public Variable(String typeName, String fieldName, boolean safeInitialValue) {
        this(typeName, fieldName);
        this.safe = safeInitialValue;
    }

    public boolean isSafe() {
        return intrinsicallySafe || safe;
    }

    public void markUnsafeMutation() {
        if(!intrinsicallySafe) safe = false;
    }

    public String getLowerCaseName() {
        return lowerCaseName;
    }
    
    /**
     * @param typeName the declared variable type, for example String, Integer, List&lt;Integer&gt;
     * @return true if this type cannot contain SOQL injection attacks. For example a number cannot contain non-numerics.
     */
    private static boolean isSafeVariableType(String typeName) {
        Matcher matcher = COLLECTION_TYPE_REGEX.matcher(typeName);
        if(matcher.matches()) {
            typeName = matcher.group(2);
        }
        return SAFE_VARIABLE_TYPES.contains(typeName.toLowerCase(Locale.ROOT));
    }

    public String getTypeName() {
        return typeName;
    }
}