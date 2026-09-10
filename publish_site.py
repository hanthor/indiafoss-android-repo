"""Copy only the public catalogue files from a generated repo/ into a Pages site tree.

Takes the `repo/` produced by `build_catalogue.py` and writes `<site>/fdroid/repo/`
containing the index files, signed JARs, icons and the exact APKs, plus a
`.nojekyll` marker. `status/`, `config.yml`, keystores and anything else are never
copied. The result is meant to be checked again with
`verify_index.py --deployable` before it is deployed; this script never deploys.
"""
import argparse
from pathlib import Path
import shutil

from verify_apk import require
from verify_index import PUBLIC_DIRECTORIES, PUBLIC_FILES, SECRET_SUFFIXES


def public_paths(repo):
    for path in sorted(repo.iterdir()):
        require(not path.is_symlink(), f"Refusing symlink {path.name}")
        require(path.name != "config.yml" and path.suffix not in SECRET_SUFFIXES,
                f"Secret-looking file in repo output: {path.name}")
        if path.is_dir():
            if PUBLIC_DIRECTORIES.match(path.name):
                yield path
        elif path.name in PUBLIC_FILES or (path.suffix == ".apk" and "_" in path.stem):
            yield path


def assemble(repo, site):
    require(repo.is_dir(), f"Not a directory: {repo}")
    require((repo / "entry.jar").is_file(), "Only a signed catalogue (entry.jar) can be published")
    target = site / "fdroid" / "repo"
    require(not site.exists(), f"Site directory already exists: {site}")
    target.mkdir(parents=True)
    copied = []
    for path in public_paths(repo):
        if path.is_dir():
            shutil.copytree(path, target / path.name, symlinks=False)
        else:
            shutil.copyfile(path, target / path.name)
        copied.append(path.name)
    (site / ".nojekyll").write_text("")
    return copied


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    parser.add_argument("site", type=Path)
    args = parser.parse_args()
    for name in assemble(args.repo, args.site):
        print(name)


if __name__ == "__main__":
    main()
