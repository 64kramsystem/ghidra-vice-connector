"""Compose the VICE schema from Ghidra 12.2's shared schema fragments."""
from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path
import xml.etree.ElementTree as ET


def compose(install: Path, base: Path, output: Path) -> None:
    metadata = dict(line.split("=", 1) for line in
        (install / "Ghidra/application.properties").read_text().splitlines()
        if "=" in line and not line.startswith("#"))
    if metadata.get("application.version") != "12.2":
        raise ValueError("Schema generation requires Ghidra 12.2")
    fragments = install / "Ghidra/Debug/Debugger-rmi-trace/pypkg/src/ghidratrace/xml"
    templates = {}
    for name in ("common.xml", "breakpointsFlat.xml"):
        for schema in ET.parse(fragments / name).getroot():
            templates[schema.get("name")] = schema
    custom = ET.parse(base).getroot()
    renamed = {schema.get("inherit"): schema.get("name") for schema in custom
               if schema.get("inherit")}
    result = ET.Element("context")
    for schema in custom:
        parent = schema.attrib.pop("inherit", None)
        remove = schema.attrib.pop("remove-attribute", None)
        merged = deepcopy(templates[parent]) if parent else ET.Element("schema")
        merged.attrib.update(schema.attrib)
        for child in schema:
            key = (child.tag, child.get("name"), child.get("from"))
            for previous in list(merged):
                if (previous.tag, previous.get("name"), previous.get("from")) == key:
                    merged.remove(previous)
            merged.append(deepcopy(child))
        for child in list(merged):
            if remove and child.tag == "attribute" and child.get("name") == remove:
                merged.remove(child)
        for child in merged:
            if child.get("schema") in renamed:
                child.set("schema", renamed[child.get("schema")])
        result.append(merged)
    result.insert(0, ET.Comment(" Generated from schema-base.xml and Ghidra 12.2; do not edit. "))
    tree = ET.ElementTree(result)
    ET.indent(tree, space="    ")
    output.write_text(ET.tostring(result, encoding="unicode") + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("install", type=Path)
    parser.add_argument("--base", type=Path, default=Path("src/main/py/src/vice/schema-base.xml"))
    parser.add_argument("--output", type=Path, default=Path("src/main/py/src/vice/schema.xml"))
    args = parser.parse_args()
    compose(args.install, args.base, args.output)
