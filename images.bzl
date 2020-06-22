"""
buildfarm images that can be imported into other WORKSPACE files
"""

load("@io_bazel_rules_docker//repositories:deps.bzl", container_deps = "deps")
load(
    "@io_bazel_rules_docker//java:image.bzl",
    _java_image_repos = "repositories",
)

load("@io_bazel_rules_docker//container:container.bzl", "container_pull")

def buildfarm_images():
    container_deps()

    container_pull(
        name = "java_base",
        tag = "11",
        registry = "gcr.io",
        repository = "distroless/java",
    )

    _java_image_repos()
