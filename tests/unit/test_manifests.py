"""Dependency manifest parsing tests (no network, no vulnerability matching)."""
from vulnmind.analysis.manifests import parse_manifest


def names(inventory):
    return [(dependency.name, dependency.version, dependency.ecosystem) for dependency in inventory.dependencies]


def test_requirements_with_pins_comments_and_markers():
    content = """
# runtime
fastapi==0.115.0
pydantic>=2.7,<3   # inline comment
requests[socks]==2.32.3 ; python_version >= "3.9"
httpx
-r other.txt
"""
    inventory = parse_manifest("requirements.txt", content)
    assert names(inventory) == [("fastapi", "==0.115.0", "pypi"),
                                ("pydantic", ">=2.7,<3", "pypi"),
                                ("requests", "==2.32.3", "pypi"),
                                ("httpx", None, "pypi")]
    assert inventory.skipped == 0


def test_package_json_runtime_and_dev():
    content = """{
      "dependencies": {"express": "^4.19.2", "lodash": "4.17.21"},
      "devDependencies": {"jest": "^29.7.0"}
    }"""
    inventory = parse_manifest("package.json", content)
    assert names(inventory) == [("express", "^4.19.2", "npm"), ("lodash", "4.17.21", "npm"),
                                ("jest", "^29.7.0", "npm")]
    assert [dependency.scope for dependency in inventory.dependencies] == ["runtime", "runtime", "development"]


def test_pyproject_and_cargo():
    content = """
[project]
name = "demo"
dependencies = ["langgraph>=1,<2", "pydantic-settings>=2"]
[project.optional-dependencies]
test = ["pytest>=8"]
"""
    inventory = parse_manifest("pyproject.toml", content)
    assert names(inventory) == [("langgraph", ">=1,<2", "pypi"), ("pydantic-settings", ">=2", "pypi"),
                                ("pytest", ">=8", "pypi")]
    cargo = parse_manifest("Cargo.toml", '[dependencies]\nserde = "1.0"\n')
    assert names(cargo) == [("serde", "1.0", "cargo")]


def test_go_mod():
    content = """
module example.test/app

go 1.22

require github.com/gin-gonic/gin v1.10.0
require (
\tgithub.com/stretchr/testify v1.9.0
)
"""
    inventory = parse_manifest("go.mod", content)
    assert names(inventory) == [("github.com/gin-gonic/gin", "v1.10.0", "go"), ("github.com/stretchr/testify", "v1.9.0", "go")]


def test_malformed_inputs_are_counted_not_guessed():
    assert parse_manifest("package.json", "{not json").skipped == 1
    assert parse_manifest("pyproject.toml", "[[[").skipped == 1
    inventory = parse_manifest("requirements.txt", "   \n==1.0\n!!!\n")
    assert inventory.dependencies == [] and inventory.skipped == 2
    assert parse_manifest("notes.txt", "anything").dependencies == []


def test_dependency_count_is_capped():
    from vulnmind.analysis.manifests import MAX_DEPENDENCIES
    content = "\n".join(f"package{i}==1.0" for i in range(MAX_DEPENDENCIES + 10))
    assert len(parse_manifest("requirements.txt", content).dependencies) == MAX_DEPENDENCIES
