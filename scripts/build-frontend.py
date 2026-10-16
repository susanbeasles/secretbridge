#!/usr/bin/env python3
"""Compile recovered Java against an explicitly selected installed JetBrains SDK."""
import argparse
import io
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ide-home', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    ide = args.ide_home.resolve()
    javac = ide / 'Contents/jbr/Contents/Home/bin/javac'
    libs = sorted((ide / 'Contents/lib').rglob('*.jar'))
    sources = sorted((ROOT / 'frontend/src/main/java').rglob('*.java'))
    if not javac.is_file() or not libs or not sources:
        parser.error('installed IDE JDK, libraries and recovered source are required')
    if args.output.exists():
        parser.error('output must be new; existing artifact preserved')
    original = ROOT / 'secretbridge/lib/secretbridge-0.1.0.jar'
    with tempfile.TemporaryDirectory(prefix='secretbridge-compile-') as task:
        classes = Path(task) / 'classes'
        subprocess.run([str(javac), '--release', '21', '-classpath', ':'.join(map(str, libs)), '-d', str(classes), *map(str, sources)], check=True, timeout=120)
        tests = sorted((ROOT / 'frontend/src/test/java').rglob('*.java'))
        test_classes = Path(task) / 'test-classes'
        classpath = ':'.join([str(classes), *map(str, libs)])
        subprocess.run([str(javac), '--release', '21', '-classpath', classpath, '-d', str(test_classes), *map(str, tests)], check=True, timeout=120)
        fixture = Path(task) / 'fixture'
        fixture.mkdir()
        subprocess.run([str(javac.with_name('java')), '-Djava.awt.headless=true', '-classpath', str(test_classes) + ':' + classpath, 'me.vespoli.secretbridge.EngineContract', str(fixture)], check=True, timeout=60)
        compiled = {p.relative_to(classes).as_posix(): p.read_bytes() for p in classes.rglob('*.class')}
        jar_bytes = io.BytesIO()
        with zipfile.ZipFile(original) as old, zipfile.ZipFile(jar_bytes, 'w', zipfile.ZIP_DEFLATED) as new:
            expected = {n for n in old.namelist() if n.endswith('.class')}
            if set(compiled) != expected:
                raise RuntimeError('recovered class inventory differs from shipped plugin')
            for entry in old.infolist():
                if not entry.filename.endswith('.class'):
                    data = old.read(entry.filename)
                    if entry.filename in ('secretbridge.py', 'requirements.txt'):
                        data = (ROOT / 'backend' / entry.filename).read_bytes()
                    new.writestr(entry, data)
            for name, data in sorted(compiled.items()):
                entry = zipfile.ZipInfo(name, (1980, 2, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                new.writestr(entry, data)
        # Exclusive creation handles races as well as the earlier existence check.
        with args.output.open('xb') as output, zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as package:
            package.writestr('secretbridge/lib/secretbridge-0.1.0.jar', jar_bytes.getvalue())
            options = ROOT / 'secretbridge/lib/secretbridge-0.1.0-searchableOptions.jar'
            package.writestr('secretbridge/lib/' + options.name, options.read_bytes())
    with zipfile.ZipFile(args.output) as package:
        if package.testzip() is not None:
            raise RuntimeError('package CRC check failed')
    print(f'Compiled {len(sources)} recovered Java sources; packaged {len(compiled)} classes: {args.output}')
    print('Installation, UI behavior and live provider publication remain unqualified.')

if __name__ == '__main__':
    main()
