use std::ops::Range;
use std::thread::sleep;
use std::time::Duration;

use crate::auth_monitor::AuthMonitor;
use crate::auth_monitor_options::AuthMonitorOptions;
use crate::auth_monitor_params::AuthMonitorParams;
use crate::test_utils::test_file::TestFile;

struct AuthMonitorTest {
    auth_monitor: AuthMonitor,
}

impl AuthMonitorTest {
    pub fn new(path: &str, options: AuthMonitorOptions) -> AuthMonitorTest {
        println!("Creating AuthMonitor with options: {}", options);
        let auth_monitor = AuthMonitor::new(AuthMonitorParams {
            filepath: String::from(path),
            options,
        })
        .expect("Error creating AuthMonitor");
        return AuthMonitorTest { auth_monitor };
    }

    pub fn expect_no_update_callback_call(&mut self) {
        self.auth_monitor.update(|| {
            panic!("Callback call was not expected");
        });
    }

    pub fn expect_update_callback_is_called_once(&mut self) {
        let mut call_count = 0;
        self.auth_monitor.update(|| {
            call_count += 1;
        });
        assert_eq!(call_count, 1, "One callback call was expected")
    }
}

const MAX_FAILED_ATTEMPTS_TEST_RANGE: Range<i32> = 2..15;

#[test]
fn when_file_does_not_exist_then_changes_are_monitored_after_it_is_created() {
    let mut file = TestFile::empty();
    file.remove();

    let options = AuthMonitorOptions::default();
    let mut test = AuthMonitorTest::new(file.path(), options);
    test.expect_no_update_callback_call();

    file.create();

    for i in 0usize..(options.max_failed_attempts - 1) as usize {
        file.write_auth_failed_message(i);
        test.expect_no_update_callback_call();
    }

    file.write_auth_failed_message(0);
    test.expect_update_callback_is_called_once();
}

#[test]
pub fn when_auth_failure_limit_is_reached_then_update_callback_is_invoked() {
    for max_failed_attempts in MAX_FAILED_ATTEMPTS_TEST_RANGE {
        let mut file = TestFile::not_empty();
        let options = AuthMonitorOptions {
            max_failed_attempts,
            ..AuthMonitorOptions::default()
        };
        let mut test = AuthMonitorTest::new(file.path(), options);
        test.expect_no_update_callback_call();

        for i in 0usize..(max_failed_attempts - 1) as usize {
            file.write_auth_failed_message(i);
            test.expect_no_update_callback_call();
        }

        for i in 0usize..(max_failed_attempts * 2) as usize {
            file.write_other_message(i);
            test.expect_no_update_callback_call();
        }

        file.write_auth_failed_message(0);
        test.expect_update_callback_is_called_once();
    }
}

#[test]
pub fn when_auth_failure_limit_is_reached_between_updates_then_next_update_invokes_callback() {
    for max_failed_attempts in MAX_FAILED_ATTEMPTS_TEST_RANGE {
        let mut file = TestFile::not_empty();
        let options = AuthMonitorOptions {
            max_failed_attempts,
            ..AuthMonitorOptions::default()
        };
        let mut test = AuthMonitorTest::new(file.path(), options);
        test.expect_no_update_callback_call();

        file.write_auth_failed_messages(max_failed_attempts as usize);
        file.write_other_messages(max_failed_attempts as usize);

        test.expect_update_callback_is_called_once();
    }
}

#[test]
pub fn when_reset_time_has_passed_then_reset_failed_attempt_counter() {
    let mut file = TestFile::not_empty();
    let options = AuthMonitorOptions {
        reset_after_seconds: 5,
        ..AuthMonitorOptions::default()
    };
    let mut test = AuthMonitorTest::new(file.path(), options);
    test.expect_no_update_callback_call();

    let failed_attempts_safe_limit = (options.max_failed_attempts - 1) as usize;

    for i in 0usize..failed_attempts_safe_limit {
        file.write_auth_failed_message(i);
        test.expect_no_update_callback_call();
    }

    let sleep_duration = Duration::from_secs((options.reset_after_seconds + 1) as u64);
    println!("Sleeping for {} sec", sleep_duration.as_secs());
    sleep(sleep_duration);

    for i in 0usize..failed_attempts_safe_limit {
        file.write_auth_failed_message(i);
        test.expect_no_update_callback_call();
    }

    file.write_auth_failed_message(0);
    test.expect_update_callback_is_called_once();
}

#[test]
pub fn when_ignore_subsequent_fails_duration_has_not_elapsed_then_update_callback_is_not_called() {
    let mut file = TestFile::not_empty();
    let options = AuthMonitorOptions {
        ignore_subsequent_fails_ms: 10,
        ..AuthMonitorOptions::default()
    };
    let mut test = AuthMonitorTest::new(file.path(), options);
    test.expect_no_update_callback_call();

    let max_failed_attempts = options.max_failed_attempts as usize;

    for i in 0usize..max_failed_attempts {
        file.write_auth_failed_message(i);
        test.expect_no_update_callback_call();
    }

    test.expect_no_update_callback_call();
}

#[test]
pub fn when_ignore_subsequent_fails_duration_has_elapsed_then_update_callback_is_called() {
    let mut file = TestFile::not_empty();
    let options = AuthMonitorOptions {
        ignore_subsequent_fails_ms: 10,
        ..AuthMonitorOptions::default()
    };
    let mut test = AuthMonitorTest::new(file.path(), options);
    test.expect_no_update_callback_call();

    let max_failed_attempts = options.max_failed_attempts as usize;
    let sleep_duration = Duration::from_millis((options.ignore_subsequent_fails_ms + 1) as u64);

    for i in 0usize..max_failed_attempts {
        file.write_auth_failed_message(i);
        println!("Sleeping for {} ms", sleep_duration.as_millis());
        sleep(sleep_duration);
    }

    test.expect_update_callback_is_called_once();
}

#[test]
fn when_file_is_deleted_and_new_one_is_created_then_changes_are_still_monitored() {
    let mut file = TestFile::not_empty();
    let options = AuthMonitorOptions::default();
    let mut test = AuthMonitorTest::new(file.path(), options);
    file.remove();
    test.expect_no_update_callback_call();

    file.create();
    test.expect_no_update_callback_call();

    file.write_auth_failed_messages(options.max_failed_attempts as usize);
    test.expect_update_callback_is_called_once();
}

#[test]
fn when_file_is_renamed_and_new_one_is_created_then_changes_are_still_monitored() {
    let mut file = TestFile::not_empty();
    let options = AuthMonitorOptions::default();
    let mut test = AuthMonitorTest::new(file.path(), options);

    let filepath = String::from(file.path());
    let new_filepath = format!("{}.bak", file.path());
    file.rename(&new_filepath);
    test.expect_no_update_callback_call();

    let mut new_file = TestFile::new(&filepath);
    test.expect_no_update_callback_call();
    new_file.write_auth_failed_messages(options.max_failed_attempts as usize);
    test.expect_update_callback_is_called_once();
}

#[test]
fn when_file_is_truncated_then_changes_are_still_monitored() {
    let mut file = TestFile::not_empty();
    file.write_other_messages(5);

    let options = AuthMonitorOptions::default();
    let mut test = AuthMonitorTest::new(file.path(), options);

    file.truncate();
    test.expect_no_update_callback_call();

    file.write_auth_failed_messages(options.max_failed_attempts as usize);
    test.expect_update_callback_is_called_once();
}
