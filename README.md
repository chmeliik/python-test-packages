# Python test packages

A bunch of mock packages for testing the magical script that determines the name
and version of a package from `setup.cfg` or `setup.py`.

## Usage

```shell
./pip_magic.py package_01
```

You can compare the output of the above with:

```shell
cd package_01/
python setup.py sdist
```
