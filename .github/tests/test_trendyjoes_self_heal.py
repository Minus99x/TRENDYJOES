import datetime as dt
import os
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import trendyjoes_self_heal as observer
from trendyjoes_self_heal import eligible_for_retry, hourly_action

REPO = 'Minus99x/TRENDYJOES'
NOW = dt.datetime(2026, 10, 25, 17, 43, tzinfo=dt.timezone.utc)


def example(**overrides):
    r = {'repository': {'full_name': REPO},
         'name': 'TrendyJoes Autonomous Studio Engineering',
         'head_branch': 'main', 'run_attempt': 1, 'status': 'completed',
         'conclusion': 'failure', 'event': 'schedule',
         'created_at': '2026-10-25T17:05:00Z'}
    r.update(overrides)
    return r


class RecoveryTests(unittest.TestCase):
    def test_failure_retryable(self):
        self.assertTrue(eligible_for_retry(example(), REPO))

    def test_success_is_not_retried(self):
        self.assertFalse(eligible_for_retry(example(conclusion='success'), REPO))

    def test_never_repeat_after_three(self):
        self.assertFalse(eligible_for_retry(example(run_attempt=3), REPO))

    def test_ignore_other_repository(self):
        self.assertFalse(eligible_for_retry(example(repository={'full_name': 'attacker/fork'}), REPO))

    def test_ignore_other_branch(self):
        self.assertFalse(eligible_for_retry(example(head_branch='dev/untrusted'), REPO))

    def test_ignore_running(self):
        self.assertFalse(eligible_for_retry(example(status='in_progress'), REPO))

    def test_dispatch_when_hour_missing(self):
        self.assertEqual(hourly_action([], NOW), 'dispatch')

    def test_do_not_dispatch_before_grace(self):
        self.assertEqual(hourly_action([], NOW.replace(minute=20)), 'too_early')

    def test_do_not_dispatch_if_hourly_trigger_observed(self):
        self.assertEqual(hourly_action([example()], NOW), 'observed')

    def test_do_not_dispatch_if_recent_push_runs_worker(self):
        self.assertEqual(hourly_action([example(event='push',created_at='2026-10-25T17:40:00Z')], NOW), 'observed')

    def test_do_not_dispatch_if_prior_hour_still_running(self):
        self.assertEqual(hourly_action([example(status='in_progress',created_at='2026-10-25T16:05:00Z')], NOW), 'active')

    def test_old_completed_run_doesnt_count(self):
        self.assertEqual(hourly_action([example(created_at='2026-10-25T16:05:00Z')], NOW), 'dispatch')


class RecoveryExecutionTests(unittest.TestCase):
    def exercise(self, run, quota=False, allow_retry=True):
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': REPO}), \
             patch.object(observer, 'github', return_value=run) as api, \
             patch.object(observer, 'quota_blocked', return_value=quota) as classification, \
             patch.object(observer, 'note') as note:
            observer.retry(123, run['run_attempt'], allow_retry=allow_retry)
            return api.call_args_list, classification.call_count, str(note.call_args_list)

    def test_quota_stops_immediate_retry_and_reports_block(self):
        calls, count, notes = self.exercise(example(id=123), quota=True)
        self.assertEqual(len(calls), 1)
        self.assertEqual(count, 1)
        self.assertIn('BLOCKED', notes)
        self.assertIn('No code delivery', notes)

    def test_exhaustion_reports_worker_failure_without_failing_observer(self):
        calls, _, notes = self.exercise(example(id=123, run_attempt=3))
        self.assertEqual(len(calls), 1)
        self.assertIn('remains FAILED', notes)

    def test_transient_failure_still_retries(self):
        calls, _, _ = self.exercise(example(id=123))
        self.assertEqual(calls[-1].args, ('POST', 'actions/runs/123/rerun-failed-jobs', {}))

    def test_push_audit_cannot_retry(self):
        calls, _, _ = self.exercise(example(id=123), allow_retry=False)
        self.assertEqual(len(calls), 1)

    def test_success_never_inspects_logs(self):
        calls, count, _ = self.exercise(example(id=123, conclusion='success'))
        self.assertEqual((len(calls), count), (1, 0))

    def test_untrusted_run_rejected_before_reading_logs(self):
        with self.assertRaisesRegex(RuntimeError, 'Untrusted'):
            self.exercise(example(id=123, head_branch='attacker'))

    def test_attested_generation_quota_is_detected(self):
        jobs = {'jobs': [{'id': 456, 'conclusion': 'failure', 'steps': [{
            'name': 'Implement and test next unmet functional Studio objective', 'conclusion': 'failure'}]}]}
        with patch.object(observer, 'github', side_effect=[jobs, '2026-10-29 You have exceeded your monthly quota (Request ID: test)']) as api:
            self.assertTrue(observer.quota_blocked(example(id=123)))
            self.assertIn('/attempts/1/jobs', api.call_args_list[0].args[1])

    def test_unrelated_job_failure_does_not_classify_quota(self):
        jobs = {'jobs': [{'id': 456, 'conclusion': 'failure', 'steps': [{'name': 'Run tests', 'conclusion': 'failure'}]}]}
        with patch.object(observer, 'github', return_value=jobs) as api:
            self.assertFalse(observer.quota_blocked(example(id=123)))
            self.assertEqual(api.call_count, 1)

    def test_generation_error_without_quota_is_not_suppressed(self):
        jobs = {'jobs': [{'id': 456, 'conclusion': 'failure', 'steps': [{
            'name': 'Implement and test next unmet functional Studio objective', 'conclusion': 'failure'}]}]}
        with patch.object(observer, 'github', side_effect=[jobs, 'connection timed out']):
            self.assertFalse(observer.quota_blocked(example(id=123)))

    def test_redirect_does_not_forward_credentials(self):
        import urllib.request
        request = urllib.request.Request('https://api.github.com/logs', headers={'Authorization': 'Bearer test'})
        redirected = observer.SafeRedirect().redirect_request(request, None, 302, 'Found', {}, 'https://logs.example/signed')
        self.assertIsNone(redirected.get_header('Authorization'))


if __name__ == '__main__':
    unittest.main()
