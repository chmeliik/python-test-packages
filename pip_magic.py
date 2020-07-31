#!/usr/bin/env python3
import ast
import configparser
import importlib
import sys
from pathlib import Path

import pkg_resources


# Version parsing


def any_to_version(obj):
    # https://github.com/pypa/setuptools/blob/ba209a15247b9578d565b7491f88dc1142ba29e4/setuptools/config.py#L535
    version = obj
    if version is None:
        return None

    if not isinstance(obj, str):
        if hasattr(version, "__iter__"):
            version = ".".join(map(str, version))
        else:
            version = str(version)

    return pkg_resources.safe_version(version)


# SETUP.CFG


def get_metadata_from_setup_cfg(dir_path="."):
    setup_path = Path(dir_path)/"setup.cfg"
    if not setup_path.is_file():
        return None, None
    parsed_setup = configparser.ConfigParser()
    with setup_path.open() as f:
        parsed_setup.read_file(f)
    name = get_metadata_value(parsed_setup, "name")
    version = get_metadata_value(parsed_setup, "version")
    if version is not None:
        version = resolve_pkg_version(version, dir_path)
    return name, any_to_version(version)


def get_metadata_value(parsed_setup, key):
    try:
        return parsed_setup.get("metadata", key)
    except (configparser.NoSectionError, configparser.NoOptionError):
        return None


def resolve_pkg_version(version_str, dir_path="."):
    # https://setuptools.readthedocs.io/en/latest/setuptools.html#specifying-values
    if version_str.startswith("attr:"):
        attr_arg = version_str[len("attr:"):].strip()
        version = resolve_version_attr(attr_arg, dir_path)
    elif version_str.startswith("file:"):
        file_arg = version_str[len("file:"):].strip()
        version = resolve_version_file(file_arg, dir_path)
    else:
        # version attribute supports attr: and file: directives
        # assume anything else should be interpreted as the version itself
        version = version_str
    return version


def resolve_version_file(file_path, dir_path="."):
    top_dir = Path(dir_path).resolve()
    version_file = (top_dir/file_path).resolve()
    if top_dir not in version_file.parents:
        raise RuntimeError(f"Version file {file_path!r} is outside project directory")
    if not version_file.is_file():
        raise RuntimeError(f"Version file {file_path!r} does not exist or is not a file")
    return version_file.read_text().strip()


def resolve_version_attr(attr_spec, dir_path="."):
    module_import_path, _, attr_name = attr_spec.rpartition(".")
    module_import_path = module_import_path or "__init__"
    sys.path.insert(0, dir_path)
    try:
        spec = importlib.util.find_spec(module_import_path)
    except Exception as e:
        raise RuntimeError(e)
    finally:
        sys.path.pop(0)
    if spec is None:
        raise RuntimeError(f"Module {module_import_path!r} not found")
    with open(spec.origin) as f:
        module = ast.parse(f.read())
    top_level_vars = get_top_level_literal_vars(module)
    if attr_name not in top_level_vars:
        msg = f"No top-level attribute {attr_name!r} in {module_import_path!r}"
        raise RuntimeError(msg)
    return top_level_vars[attr_name]


def get_top_level_literal_vars(module_ast, before_line=None):
    if not module_ast.body:
        return {}
    if before_line is None:
        before_line = module_ast.body[-1].lineno + 1
    literal_vars = {}
    for node in module_ast.body:
        if node.lineno < before_line and isinstance(node, ast.Assign):
            try:
                value = ast.literal_eval(node.value)
            except ValueError:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    literal_vars[target.id] = value
    return literal_vars


# SETUP.PY


def get_metadata_from_setup_py(dir_path="."):
    setup_path = Path(dir_path)/"setup.py"
    if not setup_path.is_file():
        return None, None
    with setup_path.open() as f:
        setup_ast = ast.parse(f.read())
    setup_call = find_setup_call(setup_ast)
    if setup_call is None:
        raise RuntimeError(f"Setup script {str(setup_path)!r} has no setup() call")
    top_level_vars = get_top_level_literal_vars(setup_ast, setup_call.lineno)
    name = get_kwarg_value(setup_call, "name", top_level_vars)
    version = get_kwarg_value(setup_call, "version", top_level_vars)
    return name, any_to_version(version)


def find_setup_call(module_ast):
    for node in module_ast.body:
        if isinstance(node, ast.Expr) and is_setup_call(node.value):
            return node.value
    return None


def is_setup_call(node):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    return (
        isinstance(func, ast.Name) and func.id == "setup"
        or isinstance(func, ast.Attribute) and func.attr == "setup"
    )


def get_kwarg_value(call_node, kwarg_name, top_level_vars=None):
    for kw in call_node.keywords:
        if kw.arg == kwarg_name:
            try:
                return ast.literal_eval(kw.value)
            except ValueError:
                return (top_level_vars or {}).get(kw.value.id)
    return None


if __name__ == "__main__":
    if len(sys.argv) > 1:
        dir_path = sys.argv[1]
    else:
        dir_path = "."

    print("setup.cfg:")
    name, version = get_metadata_from_setup_cfg(dir_path)
    print(f"name = {name!r}, version = {version!r}")

    print("setup.py:")
    name, version = get_metadata_from_setup_py(dir_path)
    print(f"name = {name!r}, version = {version!r}")
