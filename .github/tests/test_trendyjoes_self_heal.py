import datetime as dt
import os
import sys
import unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
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


if __name__ == '__main__':
    unittest.main()
