/**
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package net.sourceforge.pmd.util.datasource.internal;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import net.sourceforge.pmd.internal.util.ShortFilenameUtil;

/**
 * DataSource implementation to read data from a {@link java.nio.file.Path}.
 * This can also be a Path inside a zip file.
 */
public class PathDataSource extends AbstractDataSource {
    private final Path path;

    /**
     * @param path the file to read
     */
    public PathDataSource(Path path) {
        this.path = path;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return Files.newInputStream(path);
    }

    @Override
    public String getNiceFileName(boolean shortNames, String inputPaths) {
        return glomName(shortNames, inputPaths);
    }

    private String getAbsoluteFilePath() {
        if ("jar".equals(path.toUri().getScheme())) {
            return URI.create(path.toUri().getSchemeSpecificPart()).getPath();
        }
        try {
            return path.toRealPath().toAbsolutePath().toString();
        } catch (IOException e) {
            return path.toAbsolutePath().toString();
        }
    }

    private String getSimpleFilePath() {
        if ("jar".equals(path.toUri().getScheme())) {
            return URI.create(path.toUri().getSchemeSpecificPart()).getPath();
        }
        return path.getName(path.getNameCount() - 1).toString();
    }

    private String glomName(boolean shortNames, String inputPaths) {
        if (shortNames) {
            if (inputPaths != null) {
                List<String> inputPathPrefixes = Arrays.asList(inputPaths.split(","));
                final String absoluteFilePath = getAbsoluteFilePath();
                return ShortFilenameUtil.determineFileName(inputPathPrefixes, absoluteFilePath);
            } else {
                // if the 'master' file is not specified, just use the file name
                return getSimpleFilePath();
            }
        }

        return getAbsoluteFilePath();
    }

    @Override
    public String toString() {
        return new StringBuilder(this.getClass().getSimpleName())
                .append('[')
                .append(path.toUri())
                .append(']')
                .toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((path == null) ? 0 : path.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        @SuppressWarnings("PMD.CloseResource")
        PathDataSource other = (PathDataSource) obj;
        if (path == null) {
            if (other.path != null) {
                return false;
            }
        } else if (!path.equals(other.path)) {
            return false;
        }
        return true;
    }


}
