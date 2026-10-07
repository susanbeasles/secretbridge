# SecretBridge for 1Password

The JetBrains plugin manages environment-isolated 1Password references, previews publication to GitHub Actions or AWS Secrets Manager, provides secret-backed run configurations and generates configuration templates. `secretbridge/lib` and the original ZIP contain the shipped 0.1.0 Java frontend and Python backend. The recovered `backend/secretbridge.py` and `backend/requirements.txt` are byte-for-byte copies of the resources in the shipped JAR; they can now be reviewed and maintained as source.

Python 3.10+ and authenticated `op`/`gh` CLIs are required. Install `backend/requirements.txt` into a dedicated Python runtime for PyNaCl GitHub encryption and Boto3 AWS operations. The manifest contains references and explicit destinations, never secret values. Environments require separate vaults; GitHub organization publication requires an explicit repository allowlist; AWS checks the expected numeric account and uses a bounded recovery period for deletions. Previewed plans must still match current metadata before apply. Independent destination writes can partially fail; inspect the returned completed and pending operations before retrying.

## Backend and package checks

```sh
python3 backend/secretbridge.py --help
python3 scripts/package-backend.py --output /absolute/path/to/new-secretbridge.zip
```

Packaging replaces only the two recovered resources in the shipped JAR and carries the existing Java frontend and searchable-options artifact. The output path must be new. This is a backend repackaging operation, not compilation of the Java frontend. Java source/build metadata is still required for a complete source build.

Install the resulting ZIP using WebStorm's Plugins → Install Plugin from Disk, then configure Settings → SecretBridge with a dedicated Python runtime, 1Password account and executable paths. Use a disposable project, vault and explicit personal GitHub/AWS destinations for publication tests; preview every plan before applying. The original artifacts are preserved.

## Current verification limits

On October 7, 2026, WebStorm 2026.2.3 (build 262.10968.77) was found on this Mac. Automated UI installation could not proceed because Computer Use permission is unavailable. The personal GitHub CLI identity is verified; the 1Password credential read timed out after restart. Real installed-plugin operation and GitHub/AWS publication remain unverified. Supply the existing Java source/build project and enable WebStorm UI access to complete those checks; no credentials should be copied into chat.
