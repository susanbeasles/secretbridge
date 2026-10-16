# SecretBridge for 1Password

The JetBrains plugin manages environment-isolated 1Password references, previews publication to GitHub Actions or AWS Secrets Manager, provides secret-backed run configurations and generates configuration templates. `secretbridge/lib` and the original ZIP contain the shipped 0.1.0 Java frontend and Python backend. The recovered `backend/secretbridge.py` and `backend/requirements.txt` are byte-for-byte copies of the resources in the shipped JAR; they can now be reviewed and maintained as source.

Python 3.10+ and authenticated `op`/`gh` CLIs are required. Install `backend/requirements.txt` into a dedicated Python runtime for PyNaCl GitHub encryption and Boto3 AWS operations. The manifest contains references and explicit destinations, never secret values. Environments require separate vaults; GitHub organization publication requires an explicit repository allowlist; AWS checks the expected numeric account and uses a bounded recovery period for deletions. Previewed plans must still match current metadata before apply. Independent destination writes can partially fail; inspect the returned completed and pending operations before retrying.

## Backend and package checks

```sh
python3 backend/secretbridge.py --help
python3 scripts/package-backend.py --output /absolute/path/to/new-secretbridge.zip
```

Packaging replaces only the two recovered resources in the shipped JAR and carries the existing Java frontend and searchable-options artifact. The output path must be new. This is a backend repackaging operation, not compilation of the Java frontend. The recovered frontend can now be compiled using the separate source build below.

Install the resulting ZIP using WebStorm's Plugins → Install Plugin from Disk, then configure Settings → SecretBridge with a dedicated Python runtime, 1Password account and executable paths. Use a disposable project, vault and explicit personal GitHub/AWS destinations for publication tests; preview every plan before applying. The original artifacts are preserved.

## Current verification limits

On October 7, 2026, WebStorm 2026.2.3 (build 262.10968.77) was found on this Mac. Automated UI installation could not proceed because Computer Use permission is unavailable. The personal GitHub CLI identity is verified; the 1Password credential read timed out after restart. Real installed-plugin operation and GitHub/AWS publication remain unverified. The frontend has since been reconstructed and compiled; installed UI and real provider checks remain blocked by unavailable UI access and provider authentication. No credentials should be copied into chat.

## Recovered frontend source build

`frontend/src/main/java` contains seven Java sources reconstructed from the shipped
JAR with CFR 0.152, then repaired where decompilation produced invalid anonymous
class references, constructor arguments, local types, null-check formatting and
stream cleanup. This is maintainable recovered source, not the original source
or proof of bytecode equivalence. `frontend/RECOVERY.json` records input/tool
hashes and the reconstruction repairs. All original JARs and ZIPs are preserved.

```sh
python3 scripts/build-frontend.py --ide-home /Applications/WebStorm.app --output /absolute/path/to/new-secretbridge.zip
```

The build uses the explicitly selected installed IDE's JDK and libraries, targets
Java 21, runs headless manifest/stream checks, requires the same 16 class names as
the shipped plugin, and replaces Java classes plus backend resources in a new
package. No implicit download or IDE installation occurs. Compilation against
WebStorm 2026.2.3 passed on this Mac; compatibility with older IDE builds is not
established. The existing plugin metadata is retained for review.

Headless checks verify manifest round-trip, refusal to replace a symlink manifest,
missing-project rejection, stream handling and temporary-file cleanup. Package
checks verified CRCs, exact non-class resources and searchable-options bytes, and
refusal to overwrite an existing artifact. IDE installation, interactive tool
windows/completion/run configurations and live 1Password/GitHub/AWS publication
still require separate verification.

## Offline IDE compatibility check

Using the official JetBrains Plugin Verifier 1.410:

```sh
python3 scripts/verify-plugin.py --ide-home /Applications/WebStorm.app --verifier /absolute/path/to/verifier-cli-1.410-all.jar --plugin /absolute/path/to/new-secretbridge.zip --reports /absolute/path/to/new-report-directory
```

The script runs offline with a two-minute limit, retains verifier output and
requires exactly one `Compatible` verdict. Existing report directories are
rejected so stale results cannot pass a new package. It does not install plugins,
open the IDE or change user settings. The recovered package passed against
installed WebStorm `WS-262.10968.77` on October 7, 2026. The IDE layout produced
warnings for missing unrelated bundled module JARs; the verifier nevertheless
completed this plugin's check with no compatibility problems. This verdict does
not establish UI behavior, live provider access or older IDE compatibility.
