#!/usr/bin/env python3
"""Build the AX-Clarity Ghidra extension without Gradle.

  python tools/build.py "C:/ghidra_12.1.2_PUBLIC"           # build dist/*.zip
  python tools/build.py "C:/ghidra_12.1.2_PUBLIC" install   # also install for the current user

The Java sources in src/main/java are compiled against the given Ghidra into
lib/AX-Clarity.jar, staged with extension.properties and ghidra_scripts, and
zipped in the layout that "File > Install Extensions" expects. The Ghidra
version is read from <ghidra>/Ghidra/application.properties.
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAME = "AX-Clarity"
CPSEP = ";" if os.name == "nt" else ":"


def ghidra_props(ghidra):
    props = {}
    with open(os.path.join(ghidra, "Ghidra", "application.properties"), encoding="utf-8") as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                props[k] = v
    return props


def jars(ghidra, *patterns):
    out = []
    for p in patterns:
        out += glob.glob(os.path.join(ghidra, p), recursive=True)
    return out


def run(cmd):
    shown = " ".join(cmd) if len(" ".join(cmd)) < 300 else " ".join(cmd[:4]) + " ..."
    print("+", shown, flush=True)
    subprocess.check_call(cmd)


def compile_java(ghidra, out_jar):
    srcs = glob.glob(os.path.join(ROOT, "src", "main", "java", "**", "*.java"), recursive=True)
    cp = CPSEP.join(jars(ghidra, "Ghidra/Framework/**/lib/*.jar", "Ghidra/Features/Base/lib/*.jar",
                         "Ghidra/Features/Decompiler/lib/*.jar"))
    with tempfile.TemporaryDirectory() as tmp:
        argfile = os.path.join(tmp, "args.txt")
        with open(argfile, "w", encoding="utf-8") as f:
            f.write("-cp\n\"%s\"\n" % cp.replace("\\", "/"))
            for s in srcs:
                f.write("\"%s\"\n" % s.replace("\\", "/"))
        classes = os.path.join(tmp, "classes")
        os.makedirs(classes)
        run(["javac", "--release", "21", "-encoding", "UTF-8", "-Xlint:-options", "-d", classes,
             "@" + argfile])
        os.makedirs(os.path.dirname(out_jar), exist_ok=True)
        with zipfile.ZipFile(out_jar, "w", zipfile.ZIP_DEFLATED) as z:
            for base, _, files in os.walk(classes):
                for f in files:
                    full = os.path.join(base, f)
                    z.write(full, os.path.relpath(full, classes).replace(os.sep, "/"))


def stage(ghidra, version, dest):
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    with open(os.path.join(ROOT, "extension.properties"), encoding="utf-8") as f:
        props = f.read().replace("@extversion@", version)
    with open(os.path.join(dest, "extension.properties"), "w", encoding="utf-8", newline="\n") as f:
        f.write(props)
    for f in ("Module.manifest", "LICENSE", "README.md", "README.en.md"):
        if os.path.exists(os.path.join(ROOT, f)):
            shutil.copy2(os.path.join(ROOT, f), dest)
    if os.path.isdir(os.path.join(ROOT, "ghidra_scripts")):
        shutil.copytree(os.path.join(ROOT, "ghidra_scripts"), os.path.join(dest, "ghidra_scripts"))
    compile_java(ghidra, os.path.join(dest, "lib", NAME + ".jar"))


def main():
    ap = argparse.ArgumentParser(usage="build.py <ghidra_dir> [install]")
    ap.add_argument("ghidra_dir", nargs="?", help="Ghidra install dir")
    ap.add_argument("action", nargs="?", choices=["install"], help="also install for the current user")
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR"), help=argparse.SUPPRESS)
    ap.add_argument("--install", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    a.ghidra = a.ghidra_dir or a.ghidra
    a.install = a.install or a.action == "install"
    if not a.ghidra:
        sys.exit("usage: python tools/build.py <ghidra_dir> [install]  (or set GHIDRA_INSTALL_DIR)")
    props = ghidra_props(a.ghidra)
    version = props["application.version"]
    release = props.get("application.release.name", "PUBLIC")
    build = os.path.join(ROOT, "build")
    staged = os.path.join(build, NAME)
    stage(a.ghidra, version, staged)
    dist = os.path.join(ROOT, "dist")
    os.makedirs(dist, exist_ok=True)
    zname = os.path.join(dist, f"ghidra_{version}_{release}_{NAME}.zip")
    with zipfile.ZipFile(zname, "w", zipfile.ZIP_DEFLATED) as z:
        for base, _, files in os.walk(staged):
            for f in files:
                full = os.path.join(base, f)
                z.write(full, os.path.join(NAME, os.path.relpath(full, staged)).replace(os.sep, "/"))
    print("built", zname)
    if a.install:
        if os.name == "nt":
            settings = os.path.join(os.environ["APPDATA"], "ghidra")
        else:
            settings = os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "ghidra")
        target = os.path.join(settings, f"ghidra_{version}_{release}", "Extensions", NAME)
        if os.path.exists(target):
            shutil.rmtree(target)
        shutil.copytree(staged, target)
        print("installed", target, "(restart Ghidra)")


if __name__ == "__main__":
    main()
