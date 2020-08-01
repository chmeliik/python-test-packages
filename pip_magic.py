#!/usr/bin/env python3
import ast
import configparser
import importlib
import logging
import sys
from abc import ABC, abstractmethod
from pathlib import Path

import pkg_resources


logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)


def any_to_version(obj):
    """
    Convert any python object to a version string.

    https://github.com/pypa/setuptools/blob/ba209a15247b9578d565b7491f88dc1142ba29e4/setuptools/config.py#L535

    :param any obj: object to convert to version
    :rtype: str
    """
    version = obj

    if not isinstance(version, str):
        if hasattr(version, "__iter__"):
            version = ".".join(map(str, version))
        else:
            version = str(version)

    return pkg_resources.safe_version(version)


def assert_subpath(subpath, path):
    """
    Check that `subpath` really is a subpath of `path`.

    Both `path` and `subpath` must be fully resolved before
    doing the assertion, see pathlib.Path.resolve().

    :param (str | Path) subpath: Fully resolved path
    :param (str | Path) path: Fully resolved path
    :raises ValidationError: If not subpath
    """
    try:
        Path(subpath).relative_to(Path(path))
    except ValueError:
        raise ValueError(f"{str(subpath)!r} is not a subpath of {str(path)!r}")


def get_top_level_attr(module_ast, attr_name, before_line=None):
    """
    Get attribute from module if it is defined at top level and assigned to a Python literal.

    https://github.com/pypa/setuptools/blob/ba209a15247b9578d565b7491f88dc1142ba29e4/setuptools/config.py#L36

    Note that this approach is not equivalent to the setuptools one - setuptools looks for the
    attribute starting from the top, we start at the bottom. Arguably, starting at the bottom
    makes more sense, but it should not make any real difference in practice.

    :param ast.Module module_ast: Root node of module as returned by ast.parse(<Python source>)
    :param str attr_name: Name of attribute to search for
    :param int before_line: Only look for attributes defined before this line

    :rtype: anything that can be expressed as a literal ("primitive" types, collections)
    """
    for node in reversed(module_ast.body):
        if (before_line is None or node.lineno < before_line) and isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == attr_name:
                    try:
                        return ast.literal_eval(node.value)
                    except ValueError:
                        return None


class SetupFile(ABC):
    """Abstract base class for setup.cfg and setup.py handling."""

    def __init__(self, top_dir, file_name):
        """
        Initialize a SetupFile.

        :param str top_dir: Path to root of project directory
        :param str file_name: Either "setup.cfg" or "setup.py"
        """
        self._top_dir = Path(top_dir).resolve()
        self._path = self._top_dir / file_name

    def exists(self):
        """Check if file exists."""
        return self._path.is_file()

    @abstractmethod
    def get_name(self):
        """Attempt to determine the package name. Should only be called if file exists."""

    @abstractmethod
    def get_version(self):
        """Attempt to determine the package version. Should only be called if file exists."""


class SetupCFG(SetupFile):
    """
    Parse metadata.name and metadata.version from a setup.cfg file.

    Aims to match setuptools behaviour as closely as possible, but does make
    some compromises (such as never executing arbitrary Python code).
    """

    def __init__(self, top_dir):
        """
        Initialize a SetupCFG.

        :param str top_dir: Path to root of project directory
        """
        super().__init__(top_dir, "setup.cfg")
        self._parsed = None

    def get_name(self):
        """
        Get metadata.name if present.

        :rtype: str or None
        """
        self._parse()
        name = self._get_option("metadata", "name")
        if name is None:
            log.debug("No metadata.name in setup.cfg")
        return name  # TODO: pkg_resources.safe_name?

    def get_version(self):
        """
        Get metadata.version if present.

        Partially supports the file: directive (setuptools supports multiple files
        as an argument to file:, this makes no sense for version).

        Partially supports the attr: directive (will only work if the attribute
        being referenced is assigned to a Python literal).

        :rtype: str or None
        """
        self._parse()
        version = self._get_option("metadata", "version")
        if version is not None:
            log.debug("Resolving metadata.version in setup.cfg from %r", version)
            version = self._resolve_version(version)
            if version is None:
                log.debug("Failed to resolve metadata.version in setup.cfg")
        else:
            log.debug("No metadata.version in setup.cfg")

        if version is not None:
            return any_to_version(version)
        else:
            return None

    def _parse(self):
        """Parse config file if not already parsed."""
        if self._parsed is None:
            log.debug("Parsing setup.cfg at %s", self._path)
            parsed = configparser.ConfigParser()
            with self._path.open() as f:
                parsed.read_file(f)
            self._parsed = parsed
        return self._parsed

    def _get_option(self, section, option):
        """Get option from config section, return None if missing."""
        try:
            return self._parsed.get(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return None

    def _resolve_version(self, version):
        """
        Attempt to resolve the version attribute.

        :param str version: version string, may contain file: or attr: directive
        :rtype: str or None
        """
        if version.startswith("file:"):
            file_arg = version[len("file:") :].strip()
            version = self._read_version_from_file(file_arg)
        elif version.startswith("attr:"):
            attr_arg = version[len("attr:") :].strip()
            version = self._read_version_from_attr(attr_arg)
        return version

    def _read_version_from_file(self, file_path):
        """Read version from file after making sure file is a subpath of project dir."""
        full_file_path = (self._top_dir / file_path).resolve()
        assert_subpath(full_file_path, self._top_dir)

        if full_file_path.is_file():
            version = full_file_path.read_text().strip()
            log.debug("Read version from %r: %r", file_path, version)
            return version
        else:
            log.debug("Version file %r does not exist or is not a file", file_path)
            return None

    def _read_version_from_attr(self, attr_spec):
        """
        Read version from module attribute.

        Like setuptools, will try to find the attribute by looking for Python
        literals in the AST of the module. Unlike setuptools, will not execute
        the module if this fails.

        https://github.com/pypa/setuptools/blob/ba209a15247b9578d565b7491f88dc1142ba29e4/setuptools/config.py#L354

        :param str attr_spec: "import path" of attribute, e.g. package.version.__version__
        :rtype: str or None
        """
        *attr_path, attr_name = attr_spec.split(".")
        module_name = ".".join(attr_path)
        module_name = module_name or "__init__"

        log.debug("Attempting to find attribute %r in %r", attr_name, module_name)

        parent_dir = self._top_dir
        package_dirs = self._get_package_dirs()

        # This part is lifted straight from setuptools (with minor modifications)
        if package_dirs:
            if attr_path and attr_path[0] in package_dirs:
                custom_path = Path(package_dirs[attr_path[0]])
                log.debug(
                    "Custom path was specified for module %r: %r", attr_path[0], str(custom_path)
                )
                if len(custom_path.parts) > 1:
                    parent_dir = (self._top_dir / custom_path.parent).resolve()
                    module_name = custom_path.name
                else:
                    module_name = str(custom_path)
            elif "" in package_dirs:
                custom_path = Path(package_dirs[""])
                log.debug("Custom path was specified for all root modules: %r", str(custom_path))
                parent_dir = (self._top_dir / custom_path).resolve()

        assert_subpath(parent_dir, self._top_dir)

        sys.path.insert(0, str(parent_dir))
        try:
            spec = importlib.util.find_spec(module_name)
        except Exception as e:
            log.debug("Exception when looking for module %r: %r", module_name, e)
            return None
        finally:
            sys.path.remove(str(parent_dir))

        if spec is None or spec.origin is None:
            log.debug("Could not find module %r", module_name)
            return None

        log.debug("Found source file for module %r at %r", module_name, spec.origin)
        with open(spec.origin) as f:
            try:
                module_ast = ast.parse(f.read(), f.name)
            except SyntaxError as e:
                log.debug("Syntax error when parsing module: %s", e)
                return None

        version = get_top_level_attr(module_ast, attr_name)
        if version is not None:
            log.debug("Found atribute %r in %r: %r", attr_name, module_name, version)
        else:
            log.debug("Could not find attribute %r in %r", attr_name, module_name)
        return version

    def _get_package_dirs(self):
        """
        Get options.package_dir and convert to dict if present.

        https://github.com/pypa/setuptools/blob/ba209a15247b9578d565b7491f88dc1142ba29e4/setuptools/config.py#L264

        :rtype: dict[str, str] or None
        """
        package_dir_value = self._get_option("options", "package_dir")
        if package_dir_value is None:
            return None

        if "\n" in package_dir_value:
            package_items = package_dir_value.splitlines()
        else:
            package_items = package_dir_value.split(",")

        # Strip whitespace and discard empty values
        package_items = filter(bool, (p.strip() for p in package_items))

        package_dirs = {}
        for item in package_items:
            package, sep, p_dir = item.partition("=")
            if sep:
                # Otherwise value was malformed (missing '=')
                package_dirs[package.strip()] = p_dir.strip()

        return package_dirs


if __name__ == "__main__":
    if len(sys.argv) > 1:
        dir_path = sys.argv[1]
    else:
        dir_path = "."

    setup_cfg = SetupCFG(dir_path)
    if setup_cfg.exists():
        name, version = setup_cfg.get_name(), setup_cfg.get_version()
    else:
        name, version = None, None

    print(f"name = {name!r}, version = {version!r}")
