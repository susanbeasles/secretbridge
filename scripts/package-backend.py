#!/usr/bin/env python3
"""Repackage recovered Python resources into the existing Java plugin artifact."""
import argparse
import io
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New ZIP path; existing files are never overwritten')
    args = parser.parse_args()
    base = ROOT / 'secretbridge/lib/secretbridge-0.1.0.jar'
    replacements = {name: (ROOT / 'backend' / name).read_bytes()
                    for name in ('secretbridge.py', 'requirements.txt')}
    jar_data = io.BytesIO()
    found = set()
    with zipfile.ZipFile(base) as original, zipfile.ZipFile(jar_data, 'w') as revised:
        assert original.testzip() is None, 'Original JAR is corrupt'
        for entry in original.infolist():
            basename = Path(entry.filename).name
            if basename in replacements:
                if basename in found:
                    raise ValueError('Ambiguous backend resource')
                found.add(basename)
                data = replacements[basename]
            else:
                data = original.read(entry.filename)
            revised.writestr(entry, data)
    if found != set(replacements):
        raise ValueError('Original plugin is missing a backend resource')
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as package:
        package.writestr('secretbridge/lib/secretbridge-0.1.0.jar', jar_data.getvalue())
        search = ROOT / 'secretbridge/lib/secretbridge-0.1.0-searchableOptions.jar'
        package.writestr('secretbridge/lib/' + search.name, search.read_bytes())
    with args.output.open('xb') as destination:
        destination.write(output.getvalue())
    print(args.output)

if __name__ == '__main__':
    main()
