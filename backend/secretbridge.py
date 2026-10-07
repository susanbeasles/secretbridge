#!/usr/bin/env python3
"""SecretBridge: reference-only configuration, explicit secret publication.
Python 3.10+, authenticated vendor CLIs, PyNaCl for GitHub encryption, and Boto3 for AWS operations.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
import urllib.parse
from pathlib import Path

VERSION = '0.1.0'
NAME = re.compile(r'^[A-Z_][A-Z0-9_]*$')
SLUG = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')
REF = re.compile(r'^op://([^/]+)/([^/]+)/(?:([^/]+)/)?([^/?#]+)$')
SAFE_CATEGORIES = {'SECURE_NOTE', 'API_CREDENTIAL', 'PASSWORD', 'DATABASE', 'SERVER'}

class BridgeError(Exception):
    pass

class Runner:
    def __init__(self, paths=None):
        self.paths = paths or {}
        self.aws_sessions = {}
    def aws_call(self, config, service, operation, payload=None, allow=()):
        try:
            import boto3
            from botocore.config import Config
            from botocore.exceptions import BotoCoreError, ClientError
        except ImportError:
            raise BridgeError('AWS operations require Boto3. Use Settings → SecretBridge → Prepare Python runtime.') from None
        try:
            key = (config['profile'], config['region'])
            if key not in self.aws_sessions:
                self.aws_sessions[key] = boto3.Session(profile_name=config['profile'], region_name=config['region'])
            client = self.aws_sessions[key].client(service, config=Config(
                connect_timeout=15, read_timeout=30, retries={'mode': 'standard', 'max_attempts': 2}))
            result = getattr(client, operation.replace('-', '_'))(**(payload or {}))
            return json.loads(json.dumps(result, default=str))
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code', 'UnknownError')
            if code in allow:
                return {'_error': code}
            raise BridgeError('AWS request failed: ' + code) from None
        except BotoCoreError:
            raise BridgeError('AWS profile authentication or request failed. Check your SSO session and profile.') from None
    def call(self, tool, args, data=None, allow=()):
        executable = self.paths.get(tool) or shutil.which(tool)
        if not executable:
            raise BridgeError(f'{tool} is not installed or its executable path is not configured')
        env = dict(os.environ, AWS_PAGER='', GH_PROMPT_DISABLED='1', GH_NO_UPDATE_NOTIFIER='1')
        env.pop('AWS_CLI_AUTO_PROMPT', None)
        try:
            proc = subprocess.run([executable, *args], input=data, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=env, timeout=180)
        except (OSError, subprocess.TimeoutExpired):
            raise BridgeError(f'{tool} could not complete the request') from None
        if proc.returncode:
            # Never forward vendor stderr: errors may echo secret values or request bodies.
            stderr = proc.stderr.decode(errors='replace')
            code = next((c for c in allow if c in stderr), None)
            if code:
                return {'_error': code}
            known = next((c for c in ('AccessDeniedException', 'ResourceExistsException',
                         'InvalidRequestException', 'ResourceNotFoundException',
                         'ExpiredToken', 'HTTP 403', 'HTTP 404') if c in stderr), '')
            raise BridgeError(f'{tool} request failed (exit {proc.returncode}) {known}'.strip())
        if not proc.stdout.strip():
            return {}
        try:
            return json.loads(proc.stdout)
        except (ValueError, UnicodeDecodeError):
            raise BridgeError(f'{tool} returned an unexpected response') from None


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()

def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def seal_secret(value, public_key):
    try:
        from nacl.public import PublicKey, SealedBox
    except ImportError:
        raise BridgeError('GitHub publication requires PyNaCl. Use Settings → SecretBridge → Prepare Python runtime.') from None
    try:
        key = PublicKey(base64.b64decode(public_key, validate=True))
        return base64.b64encode(SealedBox(key).encrypt(value.encode())).decode()
    except (ValueError, TypeError):
        raise BridgeError('Invalid GitHub encryption public key') from None

def required(obj, key, typ=str):
    v = obj.get(key)
    if not isinstance(v, typ) or (typ == str and (not v or v.startswith('-') or '\n' in v or '\x00' in v)):
        raise BridgeError(f'Invalid or missing {key}')
    return v

def check_keys(obj, allowed):
    if not isinstance(obj, dict):
        raise BridgeError('Expected a JSON object')
    unknown = set(obj) - set(allowed)
    if unknown:
        raise BridgeError('Unknown configuration keys: ' + ', '.join(sorted(unknown)))

def validate(config):
    check_keys(config, {'version', 'project', 'account', 'tools', 'environments'})
    if config.get('version') != 1:
        raise BridgeError('Manifest version must be 1')
    if not SLUG.fullmatch(required(config, 'project')):
        raise BridgeError('Invalid project name')
    required(config, 'account')
    tools = config.get('tools', {})
    check_keys(tools, {'op', 'gh', 'aws'})
    for key, value in tools.items():
        required(tools, key)
        if not Path(value).is_absolute():
            raise BridgeError('Tool paths must be absolute')
    envs = required(config, 'environments', dict)
    if not envs:
        raise BridgeError('At least one environment is required')
    vaults_seen = set()
    for env_name, env in envs.items():
        if not SLUG.fullmatch(env_name):
            raise BridgeError('Invalid environment name')
        check_keys(env, {'vault', 'secrets', 'github', 'aws'})
        vault = required(env, 'vault')
        if vault in vaults_seen:
            raise BridgeError('Each environment must use a separate vault')
        vaults_seen.add(vault)
        secrets = required(env, 'secrets', dict)
        for name, spec in secrets.items():
            if not NAME.fullmatch(name) or name.startswith('GITHUB_'):
                raise BridgeError('Secret names must be uppercase identifiers and cannot start with GITHUB_')
            check_keys(spec, {'ref', 'state', 'group', 'github', 'aws'})
            state = spec.get('state', 'present')
            if state not in ('present', 'absent'):
                raise BridgeError('Secret state must be present or absent')
            if state == 'present':
                match = REF.fullmatch(required(spec, 'ref'))
                if not match or match[1] != vault or any(c in spec['ref'] for c in ('\n', '\r', '\x00', '"', "'", '\\', '$', '`')):
                    raise BridgeError(f'{name}: reference must belong to the environment vault')
            for flag in ('github', 'aws'):
                if flag in spec and not isinstance(spec[flag], bool):
                    raise BridgeError(f'{flag} must be a boolean')
            if 'group' in spec:
                required(spec, 'group')
        gh = env.get('github')
        if gh is not None:
            check_keys(gh, {'scope', 'repository', 'organization', 'environment', 'repositories', 'host'})
            scope = required(gh, 'scope')
            if scope not in ('repository', 'environment', 'organization'):
                raise BridgeError('Invalid GitHub scope')
            host = gh.get('host', 'github.com')
            if not re.fullmatch(r'[a-zA-Z0-9.-]+', host):
                raise BridgeError('Invalid GitHub hostname')
            if scope in ('repository', 'environment'):
                if not re.fullmatch(r'[\w.-]+/[\w.-]+', required(gh, 'repository')):
                    raise BridgeError('Invalid GitHub repository')
            if scope == 'environment':
                required(gh, 'environment')
            if scope == 'organization':
                if not SLUG.fullmatch(required(gh, 'organization')):
                    raise BridgeError('Invalid organization')
                repos = required(gh, 'repositories', list)
                if not repos or any(not isinstance(r, str) or not SLUG.fullmatch(r) for r in repos):
                    raise BridgeError('Organization secrets require an explicit nonempty repository allowlist')
        aws = env.get('aws')
        if aws is not None:
            check_keys(aws, {'profile', 'region', 'account_id', 'prefix', 'kms_key_id', 'recovery_days'})
            required(aws, 'profile')
            if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', required(aws, 'region')):
                raise BridgeError('Invalid AWS region')
            if not re.fullmatch(r'\d{12}', required(aws, 'account_id')):
                raise BridgeError('AWS account_id must have 12 digits')
            prefix = required(aws, 'prefix')
            if not re.fullmatch(r'[a-zA-Z0-9/_+=.@-]+', prefix) or not prefix.endswith('/'):
                raise BridgeError('AWS prefix must be a valid secret-name prefix ending with /')
            if len(prefix) > 400:
                raise BridgeError('AWS prefix is too long')
            days = aws.get('recovery_days', 30)
            if not isinstance(days, int) or isinstance(days, bool) or not 7 <= days <= 30:
                raise BridgeError('AWS recovery_days must be 7–30')
            if 'kms_key_id' in aws:
                required(aws, 'kms_key_id')
    # Different environments must not write to the same cloud secret destination.
    destinations = set()
    for env_name, env in envs.items():
        for name, spec in env['secrets'].items():
            if env.get('github') and spec.get('github', True):
                gh = env['github']
                key = ('gh', gh.get('host', 'github.com'), gh['scope'],
                       gh.get('organization', gh.get('repository')), gh.get('environment'), name)
                if key in destinations:
                    raise BridgeError('Environment collision in GitHub targets')
                destinations.add(key)
            if env.get('aws') and spec.get('aws', True):
                aws = env['aws']
                key = ('aws', aws['account_id'], aws['region'], aws['prefix'] + name)
                if key in destinations:
                    raise BridgeError('Environment collision in AWS targets')
                destinations.add(key)
    return config

class Bridge:
    def __init__(self, config, runner=None):
        self.config = validate(config)
        self.runner = runner or Runner(config.get('tools'))
    def op(self, args, data=None):
        return self.runner.call('op', ['--account', self.config['account'], *args, '--format', 'json'], data)
    def environment(self, name):
        if name not in self.config['environments']:
            raise BridgeError('Unknown environment')
        return self.config['environments'][name]
    def vaults(self):
        return [{'id': v['id'], 'name': v['name']} for v in self.op(['vault', 'list'])]
    def vault_create(self, name):
        if not name or name.startswith('-'):
            raise BridgeError('Invalid vault name')
        v = self.op(['vault', 'create', name])
        return {'id': v['id'], 'name': v['name']}
    def items(self, env):
        e = self.environment(env)
        return [{'id': v['id'], 'title': v['title'], 'category': v.get('category'), 'tags': v.get('tags', [])}
                for v in self.op(['item', 'list', '--vault', e['vault']])]
    def item(self, env, item_id):
        if not item_id or item_id.startswith('-'):
            raise BridgeError('Invalid item ID')
        item = self.op(['item', 'get', item_id, '--vault', self.environment(env)['vault']])
        vault = item.get('vault', {})
        if self.environment(env)['vault'] not in (vault.get('id'), vault.get('name')):
            raise BridgeError('Item does not belong to the selected environment vault')
        return item
    def fields(self, env, item_id):
        item = self.item(env, item_id)
        # Use stable item/field IDs, including section IDs. Never return values.
        return {'id': item['id'], 'title': item['title'], 'tags': item.get('tags', []),
                'fields': [{'id': f['id'], 'label': f.get('label', f['id']), 'type': f.get('type'),
                            'ref': f"op://{self.environment(env)['vault']}/{item['id']}/" +
                            (f["section"]["id"] + '/' if f.get('section') else '') + f['id']}
                           for f in item.get('fields', []) if f.get('type') not in ('FILE', 'OTP') ]}
    def create(self, env, title, fields, tags):
        if not title or title.startswith('-') or not isinstance(fields, dict) or not fields:
            raise BridgeError('A title and at least one named field are required')
        if any(not NAME.fullmatch(k) or not isinstance(v, str) for k, v in fields.items()):
            raise BridgeError('Invalid field names or values')
        if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
            raise BridgeError('Tags must be strings')
        payload = self.op(['item', 'template', 'get', 'Secure Note'])
        payload.update(title=title, tags=tags, fields=payload.get('fields', []) + [
            {'id': uuid.uuid4().hex, 'label': k, 'type': 'CONCEALED', 'value': v}
            for k, v in fields.items()])
        item = self.op(['item', 'create', '-', '--vault', self.environment(env)['vault']], canonical(payload))
        return {'id': item['id'], 'title': item['title']}
    def edit(self, env, item_id, patch):
        check_keys(patch, {'title', 'tags', 'field_id', 'field_name', 'value', 'remove_field'})
        item = self.item(env, item_id)
        if item.get('category') not in SAFE_CATEGORIES:
            raise BridgeError('Only application-secret item categories can be edited here')
        if 'title' in patch:
            item['title'] = required(patch, 'title')
        if 'tags' in patch:
            if not isinstance(patch['tags'], list) or any(not isinstance(t, str) for t in patch['tags']):
                raise BridgeError('Tags must be strings')
            item['tags'] = patch['tags']
        if 'field_name' in patch:
            name = required(patch, 'field_name')
            if not NAME.fullmatch(name) or not isinstance(patch.get('value'), str):
                raise BridgeError('New fields require a valid name and string value')
            if any(f.get('label') == name for f in item.get('fields', [])):
                raise BridgeError('Field label already exists')
            item.setdefault('fields', []).append({'id': uuid.uuid4().hex, 'label': name,
                                                  'type': 'CONCEALED', 'value': patch['value']})
        if 'field_id' in patch:
            field_id = required(patch, 'field_id')
            matches = [f for f in item.get('fields', []) if f['id'] == field_id]
            if len(matches) != 1:
                raise BridgeError('Field does not exist')
            if patch.get('remove_field'):
                if matches[0].get('purpose'):
                    raise BridgeError('Built-in fields cannot be removed')
                item['fields'] = [f for f in item['fields'] if f['id'] != field_id]
            else:
                if not isinstance(patch.get('value'), str):
                    raise BridgeError('Field value must be a string')
                matches[0]['value'] = patch['value']
        result = self.op(['item', 'edit', item_id, '--vault', self.environment(env)['vault']], canonical(item))
        return {'id': result['id'], 'title': result['title']}
    def archive(self, env, item_id):
        self.item(env, item_id)  # Validate vault membership before archival.
        self.op(['item', 'delete', item_id, '--archive', '--vault', self.environment(env)['vault']])
        return {'archived': item_id}
    def move(self, env, item_id, target_env):
        self.item(env, item_id)
        if env == target_env:
            raise BridgeError('Choose a different destination environment')
        self.op(['item', 'move', item_id, '--current-vault', self.environment(env)['vault'],
                 '--destination-vault', self.environment(target_env)['vault']])
        return {'moved': item_id, 'destination': target_env,
                'notice': 'Refresh and rebind references: moving items can change IDs.'}
    def gh_endpoint(self, gh):
        if gh['scope'] == 'organization':
            return 'orgs/' + gh['organization'] + '/actions/secrets'
        if gh['scope'] == 'environment':
            return 'repos/' + gh['repository'] + '/environments/' + urllib.parse.quote(gh['environment'], safe='') + '/secrets'
        return 'repos/' + gh['repository'] + '/actions/secrets'
    def gh_api(self, gh, endpoint, method='GET', payload=None, paginate=False, allow=()):
        args = ['api', '--hostname', gh.get('host', 'github.com'), '--method', method, endpoint]
        if paginate:
            args += ['--paginate', '--slurp']
        if payload is not None:
            args += ['--input', '-']
        return self.runner.call('gh', args, canonical(payload) if payload is not None else None, allow)
    def github_encryption(self, gh):
        key = self.gh_api(gh, self.gh_endpoint(gh) + '/public-key')
        repositories = []
        if gh['scope'] == 'organization':
            for name in gh['repositories']:
                repository = self.gh_api(gh, 'repos/' + gh['organization'] + '/' + name)
                repositories.append(repository['id'])
        return key, repositories
    def aws(self, cfg, command, payload=None, allow=()):
        return self.runner.aws_call(cfg, 'secretsmanager', command, payload, allow)
    def identity(self, aws):
        result = self.runner.aws_call(aws, 'sts', 'get-caller-identity')
        if result.get('Account') != aws['account_id']:
            raise BridgeError('AWS profile resolves to a different account than the configured target')
        return {'account': result['Account'], 'arn': result['Arn']}
    def adopt_aws(self, env_name, name):
        env = self.environment(env_name)
        if name not in env['secrets'] or not env.get('aws'):
            raise BridgeError('Select a configured AWS secret binding')
        aws = env['aws']; self.identity(aws)
        resource = aws['prefix'] + name
        observed = self.aws(aws, 'describe-secret', {'SecretId': resource})
        tags = {t['Key']: t['Value'] for t in observed.get('Tags', [])}
        ownership = {'SecretBridgeProject': self.config['project'], 'SecretBridgeEnvironment': env_name}
        if any(k in tags and tags[k] != v for k, v in ownership.items()):
            raise BridgeError('Cannot adopt a secret owned by another project or environment')
        self.aws(aws, 'tag-resource', {'SecretId': resource,
                                    'Tags': [{'Key': k, 'Value': v} for k, v in ownership.items()]})
        return {'adopted': resource, 'notice': 'Only ownership tags changed; preview sync before publishing values.'}
    def plan(self, env_name):
        validate(self.config)
        env = self.environment(env_name)
        ops = []
        identity = None
        gh = env.get('github')
        gh_existing = {}
        if gh:
            pages = self.gh_api(gh, self.gh_endpoint(gh), paginate=True)
            gh_existing = {v['name']: v.get('updated_at') for page in pages for v in page['secrets']}
        aws = env.get('aws')
        if aws:
            identity = self.identity(aws)
        for name, spec in sorted(env['secrets'].items()):
            absent = spec.get('state') == 'absent'
            if gh and spec.get('github', True):
                exists = name in gh_existing
                if not absent or exists:
                    ops.append({'target': 'github', 'name': name, 'action': 'delete' if absent else 'set',
                                'destination': gh, 'observed': gh_existing.get(name)})
            if aws and spec.get('aws', True):
                resource = aws['prefix'] + name
                observed = self.aws(aws, 'describe-secret', {'SecretId': resource}, ('ResourceNotFoundException',))
                exists = '_error' not in observed
                if exists:
                    tags = {v['Key']: v['Value'] for v in observed.get('Tags', [])}
                    owner = {'SecretBridgeProject': self.config['project'], 'SecretBridgeEnvironment': env_name}
                    if any(tags.get(k) != v for k, v in owner.items()):
                        raise BridgeError(f'AWS secret {resource} is not owned by this project/environment')
                    if observed.get('DeletedDate') and not absent:
                        raise BridgeError(f'AWS secret {resource} is scheduled for deletion; restore it first')
                if (absent and exists and not observed.get('DeletedDate')) or not absent:
                    ops.append({'target': 'aws', 'name': name,
                                'action': 'delete' if absent else ('update' if exists else 'create'),
                                'resource': resource, 'destination': aws,
                                'observed': {'arn': observed.get('ARN'),
                                             'versions': observed.get('VersionIdsToStages', {}),
                                             'modified': observed.get('LastChangedDate'),
                                             'deleted': observed.get('DeletedDate')}})
        plan = {'version': 1, 'environment': env_name, 'manifest_digest': digest(self.config),
                'aws_identity': identity, 'operations': ops}
        plan['confirmation'] = digest(plan)
        return plan
    def resolve(self, env, name):
        spec = self.environment(env)['secrets'][name]
        match = REF.fullmatch(spec['ref'])
        item = self.item(env, match[2])
        fields = [f for f in item.get('fields', []) if (f['id'] == match[4] or f.get('label') == match[4])
                  and ((f.get('section', {}).get('id') == match[3] or
                        f.get('section', {}).get('label') == match[3]) if match[3] else not f.get('section'))]
        if len(fields) != 1 or not isinstance(fields[0].get('value'), str):
            raise BridgeError(f'{name}: reference did not resolve to exactly one string field')
        return fields[0]['value']
    def apply(self, plan):
        if not isinstance(plan, dict) or 'environment' not in plan:
            raise BridgeError('Invalid plan')
        current = self.plan(plan['environment'])
        if canonical(current) != canonical(plan):
            raise BridgeError('Plan is stale or modified. Preview again before applying.')
        env_name = current['environment']
        # Resolve every source and check size limits before the first write.
        values = {}
        for op in current['operations']:
            if op['action'] != 'delete':
                name = op['name']
                if name not in values:
                    values[name] = self.resolve(env_name, name)
                limit = 48 * 1024 if op['target'] == 'github' else 65536
                if len(values[name].encode()) > limit:
                    raise BridgeError(f'{name} exceeds the destination size limit')
        encrypted = {}
        gh_config = self.environment(env_name).get('github')
        github_writes = [o for o in current['operations'] if o['target'] == 'github' and o['action'] != 'delete']
        if github_writes:
            key, repository_ids = self.github_encryption(gh_config)
            for op in github_writes:
                payload = {'key_id': key['key_id'], 'encrypted_value': seal_secret(values[op['name']], key['key'])}
                if gh_config['scope'] == 'organization':
                    payload.update(visibility='selected', selected_repository_ids=repository_ids)
                encrypted[op['name']] = payload
        results = []
        for op in current['operations']:
            try:
                name, action, cfg = op['name'], op['action'], op['destination']
                if op['target'] == 'github':
                    endpoint = self.gh_endpoint(cfg) + '/' + name
                    self.gh_api(cfg, endpoint, 'DELETE' if action == 'delete' else 'PUT',
                                None if action == 'delete' else encrypted[name])
                else:
                    resource = op['resource']
                    if action == 'delete':
                        self.aws(cfg, 'delete-secret', {'SecretId': resource,
                                                       'RecoveryWindowInDays': cfg.get('recovery_days', 30)})
                    elif action == 'create':
                        payload = {'Name': resource, 'SecretString': values[name],
                                   'ClientRequestToken': str(uuid.uuid4()), 'Tags': [
                                       {'Key': 'SecretBridgeProject', 'Value': self.config['project']},
                                       {'Key': 'SecretBridgeEnvironment', 'Value': env_name}]}
                        if cfg.get('kms_key_id'):
                            payload['KmsKeyId'] = cfg['kms_key_id']
                        self.aws(cfg, 'create-secret', payload)
                    else:
                        payload = {'SecretId': resource, 'SecretString': values[name],
                                   'ClientRequestToken': str(uuid.uuid4())}
                        if cfg.get('kms_key_id'):
                            payload['KmsKeyId'] = cfg['kms_key_id']
                        self.aws(cfg, 'update-secret', payload)
                results.append({'target': op['target'], 'name': name, 'action': action, 'status': 'succeeded'})
            except BridgeError as exc:
                results.append({'target': op['target'], 'name': op['name'], 'action': op['action'],
                                'status': 'failed', 'error': str(exc)})
                # Independent services cannot be committed transactionally. Stop and report.
                break
        return {'complete': len(results) == len(current['operations']) and
                all(r['status'] == 'succeeded' for r in results), 'results': results,
                'pending': current['operations'][len(results):]}
    def bindings(self, env_name):
        env = self.environment(env_name)
        return [{'name': name, **spec} for name, spec in sorted(env['secrets'].items())]
    def doctor(self):
        results = []
        try:
            import nacl.public
            results.append({'tool': 'pynacl', 'status': 'available'})
        except ImportError:
            results.append({'tool': 'pynacl', 'status': 'missing', 'error': 'Prepare Python runtime in SecretBridge settings'})
        for tool, args in [('op', ['--account', self.config['account'], 'whoami', '--format', 'json']),
                           ('gh', ['api', 'user'])]:
            try:
                self.runner.call(tool, args)
                results.append({'tool': tool, 'status': 'authenticated'})
            except BridgeError as exc:
                results.append({'tool': tool, 'status': 'unavailable', 'error': str(exc)})
        seen = set()
        for env in self.config['environments'].values():
            aws = env.get('aws')
            if aws and (aws['profile'], aws['region'], aws['account_id']) not in seen:
                seen.add((aws['profile'], aws['region'], aws['account_id']))
                try:
                    results.append({'tool': 'aws', 'profile': aws['profile'], 'status': 'authenticated',
                                    **self.identity(aws)})
                except BridgeError as exc:
                    results.append({'tool': 'aws', 'profile': aws['profile'], 'status': 'unavailable', 'error': str(exc)})
        return results
    def template(self, env_name, kind, action_sha=None):
        env = self.environment(env_name)
        specs = {n: s for n, s in env['secrets'].items() if s.get('state', 'present') == 'present'}
        if kind == 'env':
            return '\n'.join(f'{n}="{s["ref"]}"' for n, s in sorted(specs.items())) + '\n'
        if kind == 'workflow-native':
            gh = env.get('github')
            if not gh:
                raise BridgeError('Configure a GitHub destination first')
            header = 'name: Application secrets\non: workflow_dispatch\npermissions: {}\njobs:\n  application:\n    runs-on: ubuntu-24.04\n'
            if gh['scope'] == 'environment':
                header += '    environment: ' + json.dumps(gh['environment']) + '\n'
            header += '    steps:\n      - name: Run application\n        env:\n'
            header += ''.join(f'          {n}: ${{{{ secrets.{n} }}}}\n' for n, s in sorted(specs.items()) if s.get('github', True))
            return header + '        run: |\n          # Replace with your application command. Never echo secret values.\n          true\n'
        if kind == 'workflow-1password':
            if action_sha is None:
                release = self.runner.call('gh', ['api', '--hostname', 'github.com',
                                                  'repos/1Password/load-secrets-action/git/ref/tags/v5'])
                obj = release.get('object', {})
                for _ in range(3):
                    if obj.get('type') != 'tag': break
                    tag = self.runner.call('gh', ['api', '--hostname', 'github.com',
                                                'repos/1Password/load-secrets-action/git/tags/' + obj['sha']])
                    obj = tag.get('object', {})
                if obj.get('type') != 'commit':
                    raise BridgeError('Could not resolve the official 1Password action release to a commit')
                action_sha = obj.get('sha')
            if not action_sha or not re.fullmatch('[0-9a-f]{40}', action_sha):
                raise BridgeError('Provide a verified 40-character commit SHA of 1Password/load-secrets-action')
            header = 'name: 1Password application secrets\non: workflow_dispatch\npermissions: {}\njobs:\n  application:\n    runs-on: ubuntu-24.04\n'
            gh = env.get('github', {})
            if gh.get('scope') == 'environment':
                header += '    environment: ' + json.dumps(gh['environment']) + '\n'
            header += ('    steps:\n      - name: Load secrets\n        uses: 1Password/load-secrets-action@' + action_sha +
                       '\n        with:\n          export-env: true\n        env:\n          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}\n')
            header += ''.join(f'          {n}: {json.dumps(s["ref"])}\n' for n, s in sorted(specs.items()) if n != 'OP_SERVICE_ACCOUNT_TOKEN')
            return header + '      - name: Run application\n        run: |\n          # Replace with your application command.\n          true\n'
        if kind in ('terraform', 'cdk', 'cloudformation'):
            aws = env.get('aws')
            if not aws:
                raise BridgeError('Configure an AWS destination first')
            names = {n: aws['prefix'] + n for n, s in specs.items() if s.get('aws', True)}
            if kind == 'terraform':
                return '# Metadata only: fetching secret values with Terraform would put them in state.\n' + ''.join(
                    f'data "aws_secretsmanager_secret" "{n.lower()}" {{\n  name = {json.dumps(resource)}\n}}\n\n'
                    for n, resource in sorted(names.items()))
            if kind == 'cdk':
                return ("import { Secret } from 'aws-cdk-lib/aws-secretsmanager';\n\n" +
                        '// Inside your stack constructor. Give runtime roles read access as needed.\n' + ''.join(
                            f'const secret_{n.lower()} = Secret.fromSecretNameV2(this, {json.dumps(n)}, {json.dumps(resource)});\n'
                            for n, resource in sorted(names.items())))
            return json.dumps({'AWSTemplateFormatVersion': '2010-09-09',
                               'Description': 'Secret name parameters; runtime consumers resolve values.',
                               'Parameters': {'Secret' + str(i): {'Type': 'String', 'Default': resource, 'Description': n}
                                              for i, (n, resource) in enumerate(sorted(names.items()), 1)}, 'Resources': {}}, indent=2) + '\n'
        raise BridgeError('Unknown template type')
    def run(self, env_name, command):
        env = self.environment(env_name)
        if not command:
            raise BridgeError('Application command is required')
        executable = self.config.get('tools', {}).get('op') or shutil.which('op')
        if not executable:
            raise BridgeError('op is not installed')
        process_env = dict(os.environ)
        process_env.pop('OP_RUN_NO_MASKING', None)
        for configured in self.config['environments'].values():
            for name in configured['secrets']:
                process_env.pop(name, None)
        for name, spec in env['secrets'].items():
            if spec.get('state', 'present') == 'present':
                process_env[name] = spec['ref']
            else:
                process_env.pop(name, None)
        # op owns resolution and output masking. No plaintext values pass through the IDE process.
        return subprocess.call([executable, '--account', self.config['account'], 'run', '--', *command],
                               env=process_env)


def load(path):
    try:
        return validate(json.loads(Path(path).read_text()))
    except (OSError, ValueError):
        raise BridgeError('Unable to read a valid secretbridge.json manifest') from None

def save(path, config):
    validate(config)
    path = Path(path)
    if path.is_symlink():
        raise BridgeError('Refusing to replace a symlinked manifest')
    tmp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with tmp.open('x') as stream:
            stream.write(json.dumps(config, indent=2) + '\n')
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)

def dispatch(bridge, req, manifest):
    action = required(req, 'action')
    env = req.get('environment')
    if action == 'adopt-aws': return bridge.adopt_aws(env, required(req, 'name'))
    if action == 'prepare-github':
        gh = bridge.environment(env).get('github')
        if not gh or gh['scope'] != 'environment':
            raise BridgeError('Configure a GitHub environment target first')
        endpoint = 'repos/' + gh['repository'] + '/environments/' + urllib.parse.quote(gh['environment'], safe='')
        existing = bridge.gh_api(gh, endpoint, allow=('HTTP 404',))
        if '_error' in existing:
            bridge.gh_api(gh, endpoint, 'PUT')
        return {'prepared': gh['environment'], 'notice': 'Existing environment protection rules are preserved.'}
    if action == 'doctor': return bridge.doctor()
    if action == 'vaults': return bridge.vaults()
    if action == 'vault-create': return bridge.vault_create(required(req, 'name'))
    if action == 'items': return bridge.items(env)
    if action == 'fields': return bridge.fields(env, required(req, 'item'))
    if action == 'create': return bridge.create(env, required(req, 'title'), required(req, 'fields', dict), req.get('tags', []))
    if action == 'edit': return bridge.edit(env, required(req, 'item'), required(req, 'patch', dict))
    if action == 'archive': return bridge.archive(env, required(req, 'item'))
    if action == 'move': return bridge.move(env, required(req, 'item'), required(req, 'destination'))
    if action == 'bindings': return bridge.bindings(env)
    if action == 'plan': return bridge.plan(env)
    if action == 'apply': return bridge.apply(required(req, 'plan', dict))
    if action == 'template': return {'content': bridge.template(env, required(req, 'kind'), req.get('action_sha'))}
    if action == 'bind':
        name, ref = required(req, 'name'), required(req, 'ref')
        e = bridge.environment(env)
        e['secrets'][name] = {'ref': ref, 'group': req.get('group', 'application')}
        save(manifest, bridge.config)
        return {'bound': name, 'ref': ref}
    if action == 'remove-binding':
        name = required(req, 'name')
        e = bridge.environment(env)
        if name not in e['secrets']: raise BridgeError('Binding does not exist')
        e['secrets'][name]['state'] = 'absent'
        save(manifest, bridge.config)
        return {'removed': name, 'notice': 'Preview and apply to remove the configured cloud copies.'}
    raise BridgeError('Unknown action')

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', default='secretbridge.json')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('rpc', help='One JSON request on stdin; metadata-only JSON response')
    sub.add_parser('doctor')
    p = sub.add_parser('plan'); p.add_argument('environment')
    p = sub.add_parser('apply'); p.add_argument('plan_file')
    p = sub.add_parser('template'); p.add_argument('environment'); p.add_argument('kind'); p.add_argument('--action-sha')
    p = sub.add_parser('run'); p.add_argument('environment'); p.add_argument('args', nargs=argparse.REMAINDER)
    ns = parser.parse_args(argv)
    try:
        if ns.command == 'rpc':
            req = json.load(sys.stdin)
            if req.get('action') == 'validate-config':
                result = {'valid': bool(validate(required(req, 'config', dict)))}
            elif req.get('action') in ('bootstrap-vaults', 'bootstrap-vault-create'):
                config = {'version': 1, 'project': 'bootstrap', 'account': required(req, 'account'),
                          'tools': req.get('tools', {}),
                          'environments': {'bootstrap': {'vault': 'bootstrap', 'secrets': {}}}}
                bridge = Bridge(config)
                result = bridge.vaults() if req['action'] == 'bootstrap-vaults' else bridge.vault_create(required(req, 'name'))
            else:
                bridge = Bridge(load(ns.manifest))
                result = dispatch(bridge, req, ns.manifest)
        else:
            bridge = Bridge(load(ns.manifest))
        if ns.command == 'rpc': pass
        elif ns.command == 'doctor': result = bridge.doctor()
        elif ns.command == 'plan': result = bridge.plan(ns.environment)
        elif ns.command == 'apply':
            plan = json.loads(Path(ns.plan_file).read_text())
            result = bridge.apply(plan.get('result', plan))
        elif ns.command == 'template':
            print(bridge.template(ns.environment, ns.kind, ns.action_sha), end=''); return 0
        else:
            args = ns.args[1:] if ns.args[:1] == ['--'] else ns.args
            return bridge.run(ns.environment, args)
        print(json.dumps({'ok': True, 'result': result}, indent=2))
        return 2 if isinstance(result, dict) and result.get('complete') is False else 0
    except (BridgeError, OSError, ValueError, KeyError, TypeError) as exc:
        # Unexpected errors are opaque; never dump tracebacks containing payloads.
        error = str(exc) if isinstance(exc, BridgeError) else 'Invalid request or operation failed'
        print(json.dumps({'ok': False, 'error': error}))
        return 1

if __name__ == '__main__':
    sys.exit(main())
