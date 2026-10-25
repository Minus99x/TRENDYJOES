"""GitHub-native recovery for TrendyJoes Studio engineering.

No checkout from the untrusted triggering run; only default-branch vetted code.
Runs are verified by GitHub API before any bounded retry/dispatch.
"""
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.request

WORKFLOW_NAME = 'TrendyJoes Autonomous Studio Engineering'
WORKFLOW_FILE = 'trendyjoes-hourly-engineering.yml'
BRANCH = 'main'
MAX_ATTEMPTS = 3
GRACE_MINUTE = 43
UTC = dt.timezone.utc


def iso_time(value):
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


def eligible_for_retry(run, repository):
    """No uncontrolled retries, success masking, or stale result races."""
    return (run.get('repository', {}).get('full_name', '').lower() == repository.lower()
            and run.get('name') == WORKFLOW_NAME
            and run.get('head_branch') == BRANCH
            and run.get('status') == 'completed'
            and run.get('conclusion') in {'failure', 'timed_out'}
            and 1 <= int(run.get('run_attempt', 0)) < MAX_ATTEMPTS)


def hourly_action(runs, now):
    """Latest hourly target must have an observed start or deliberate fallback."""
    target = now.replace(minute=5, second=0, microsecond=0)
    if now.minute < GRACE_MINUTE:
        return 'too_early'
    # Older scheduled/in-progress execution is a reason not to launch a competitor.
    if any(r.get('status') in ('queued', 'pending', 'in_progress', 'waiting') for r in runs):
        return 'active'
    if any(r.get('event') in ('schedule', 'workflow_dispatch', 'push')
           and iso_time(r['created_at']) >= target for r in runs):
        return 'observed'
    return 'dispatch'


def github(method, path, body=None):
    token = os.environ['GH_TOKEN']
    repo = os.environ['GITHUB_REPOSITORY']
    if '/' not in repo:
        raise RuntimeError('Invalid repository')
    url = f'https://api.github.com/repos/{repo}/{path}'
    data = None if body is None else json.dumps(body).encode('utf-8')
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'TrendyJoes-GitHub-Native-Recovery',
        **({'Content-Type': 'application/json'} if data is not None else {})
    })
    with urllib.request.urlopen(req, timeout=18) as response:
        payload = response.read()
        return json.loads(payload) if payload else {}


def note(message):
    print(message, flush=True)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as f:
            f.write(message + '\n\n')


def retry(run_id, expected_attempt):
    # Reread actual run to avoid duplicate recoveries when webhook was delayed.
    run = github('GET', f'actions/runs/{run_id}')
    if int(run.get('run_attempt', 0)) != expected_attempt:
        note(f'Skip race: run {run_id} moved to attempt {run.get("run_attempt")}')
        return
    if not eligible_for_retry(run, os.environ['GITHUB_REPOSITORY']):
        if run.get('conclusion') == 'success':
            note(f'Run {run_id} already succeeded; no action required.')
        elif run.get('status') != 'completed':
            note(f'Run {run_id} still active; no duplicate retry.')
        elif int(run.get('run_attempt', 0)) >= MAX_ATTEMPTS:
            raise RuntimeError(f'Run {run_id} failed after {MAX_ATTEMPTS} attempts; explicit investigation required.')
        else:
            note(f'Run {run_id} not eligible for automated retry; no action.')
        return
    github('POST', f'actions/runs/{run_id}/rerun-failed-jobs', {})
    note(f'GitHub accepted bounded failed-job retry for {run_id}: attempt {expected_attempt + 1}/{MAX_ATTEMPTS}.')


def recovery():
    event = os.environ['GITHUB_EVENT_NAME']
    repo = os.environ['GITHUB_REPOSITORY']
    if event == 'workflow_run':
        with open(os.environ['GITHUB_EVENT_PATH'], encoding='utf-8') as f:
            payload = json.load(f)
        run = payload.get('workflow_run') or {}
        if run.get('name') != WORKFLOW_NAME or run.get('head_branch') != BRANCH:
            note('Ignoring unrelated workflow_run completion.')
            return
        if run.get('repository', {}).get('full_name', '').lower() != repo.lower():
            raise RuntimeError('Repository mismatch in completion event')
        if run.get('status') == 'completed' and run.get('conclusion') == 'success':
            note(f'Observed successful engineering workflow {run.get("id")}; outcome not assumed to contain a commit.')
            return
        if run.get('status') == 'completed' and run.get('conclusion') in {'failure', 'timed_out'}:
            retry(int(run['id']), int(run['run_attempt']))
        else:
            note(f'Observed non-retryable run conclusion: {run.get("conclusion")}.')
        return
    if event in {'schedule', 'workflow_dispatch'}:
        now = dt.datetime.now(UTC)
        if event == 'schedule' and now.minute < GRACE_MINUTE:
            note(f'Observer fired early at {now.isoformat()}; leaving scheduled launcher undisturbed.')
            return
        recent = github('GET', f'actions/workflows/{WORKFLOW_FILE}/runs?per_page=15').get('workflow_runs', [])
        runs = [r for r in recent if r.get('name') == WORKFLOW_NAME and r.get('head_branch') == BRANCH]
        action = hourly_action(runs, now) if event == 'schedule' else 'manual_audit'
        note(f'Observer {event} at {now.isoformat()}: {action}; inspected {len(runs)} launcher runs.')
        if action == 'dispatch':
            github('POST', f'actions/workflows/{WORKFLOW_FILE}/dispatches', {'ref': BRANCH})
            note('Missing hourly invocation: GitHub accepted explicit workflow_dispatch fallback.')
        elif action == 'observed':
            # workflow_run event is preferred; cron catches a dropped completion webhook.
            target = now.replace(minute=5, second=0, microsecond=0)
            latest = max((r for r in runs if iso_time(r['created_at']) >= target),
                         key=lambda r: iso_time(r['created_at']), default=None)
            if latest and latest.get('conclusion') in ('failure', 'timed_out'):
                retry(int(latest['id']), int(latest.get('run_attempt', 0)))
        return
    if event == 'push':
        note('Recovery configuration verified on trusted main; no retry or dispatch for bootstrap push.')
        return
    note(f'Event {event} does not authorize recovery action.')


if __name__ == '__main__':
    try:
        recovery()
    except (RuntimeError, urllib.error.HTTPError, urllib.error.URLError) as error:
        note(f'RECOVERY FAILURE requiring follow-up: {error}')
        sys.exit(1)
