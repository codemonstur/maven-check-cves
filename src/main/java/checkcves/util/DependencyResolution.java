package checkcves.util;

import bobthebuildtool.pojos.buildfile.Dependency;
import bobthebuildtool.pojos.buildfile.Project;
import bobthebuildtool.pojos.error.DependencyResolutionFailed;
import bobthebuildtool.utils.TreeNode;
import bobthebuildtool.utils.TreeRoot;

import java.util.ArrayList;
import java.util.List;

import static bobthebuildtool.services.Functions.isNullOrEmpty;
import static bobthebuildtool.services.repository.DependencyResolver.resolveDependencies;

public enum DependencyResolution {;

    public static List<Dependency> listProjectDependencies(final Project project) throws DependencyResolutionFailed {
        return flattenTree(resolveDependencies(project));
    }

    private static List<Dependency> flattenTree(final TreeRoot<Project, Dependency> tree) {
        final List<Dependency> list = new ArrayList<>();
        for (final var child : tree.children)
            flattenTree(list, child);
        return list;
    }

    private static void flattenTree(final List<Dependency> list, final TreeNode<Dependency> node) {
        list.add(node.value);
        if (!isNullOrEmpty(node.children)) {
            for (final var child : node.children)
                flattenTree(list, child);
        }
    }
}