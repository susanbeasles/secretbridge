#!/usr/bin/env python3
"""Verify a local plugin offline against an explicitly selected installed IDE."""
import argparse
from pathlib import Path
import subprocess

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ide-home', type=Path, required=True)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--plugin', type=Path, required=True)
    parser.add_argument('--reports', type=Path, required=True)
    args = parser.parse_args()
    contents = args.ide_home.resolve() / 'Contents'
    java = contents / 'jbr/Contents/Home/bin/java'
    if not java.is_file() or not args.verifier.is_file() or not args.plugin.is_file():
        parser.error('installed IDE runtime, verifier JAR and plugin ZIP are required')
    # A fresh report directory prevents stale successful results from passing.
    args.reports.mkdir(exist_ok=False)
    with (args.reports / 'verifier.log').open('w') as log:
        subprocess.run([str(java), '-jar', str(args.verifier.resolve()), 'check-plugin', str(args.plugin.resolve()), str(contents), '-offline', '-verification-reports-dir', str(args.reports.resolve()), '-verification-reports-formats', 'plain'], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
    verdicts = list(args.reports.rglob('verification-verdict.txt'))
    if len(verdicts) != 1 or verdicts[0].read_text().strip() != 'Compatible':
        raise RuntimeError(f'exactly one Compatible verdict required; inspect {args.reports}')
    print(f'PASS: offline binary compatibility; retained verdict: {verdicts[0]}')
    print('Interactive plugin operation and provider integrations require separate qualification.')

if __name__ == '__main__':
    main()
