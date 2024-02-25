use std::env::temp_dir;

use chrono::Local;

use crate::auth_file_watcher::AuthFileWatcher;
use crate::test_utils::test_file::{rename_file, TestFile};

const AUTH_FAILED_MESSAGES: [&str; 6] = [
    "workstation sudo: pam_unix(sudo:auth): authentication failure; logname=john uid=1000 euid=0 tty=/dev/pts/7 ruser=john rhost=  user=john",
    "workstation kscreenlocker_greet: pam_unix(kde:auth): authentication failure; logname= uid=1000 euid=1000 tty= ruser= rhost=  user=john",
    "workstation dbus-daemon[1988]: [system] Failed to activate service 'org.bluez': timed out (service_start_timeout=25000ms)",
    "workstation CRON[9419]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
    "workstation CRON[9419]: pam_unix(cron:session): session closed for user root",
    "workstation PackageKit: uid 1000 is trying to obtain org.freedesktop.packagekit.system-sources-refresh auth (only_trusted:0)",
];

#[test]
fn when_monitored_file_does_not_exist_then_new_does_not_return_error() {
    let filepath_buffer = temp_dir().join("auth-monitor-non-existing-file.log");
    let filepath = filepath_buffer.to_str().expect("Error creating filepath");
    AuthFileWatcher::new(filepath).expect("Error creating AuthFileWatcher");
}

#[test]
fn when_new_line_is_added_to_file_then_update_callback_is_called() {
    let mut file = TestFile::new("auth-monitor-test");
    let mut auth_file_watcher =
        AuthFileWatcher::new(&file.filepath).expect("Error creating AuthFileWatcher");
    expect_no_update_callback_call(&mut auth_file_watcher);
    expect_update_callback_is_called_when_file_is_modified(&mut file, &mut auth_file_watcher);
}

fn expect_update_callback_is_called_when_file_is_modified(
    file: &mut TestFile,
    auth_file_watcher: &mut AuthFileWatcher,
) {
    let mut call_count = 0;
    for i in 0..10 {
        let message = AUTH_FAILED_MESSAGES[i % AUTH_FAILED_MESSAGES.len()];
        let line_to_add = create_log_line(message);
        file.write(&line_to_add);
        auth_file_watcher.update(|line| {
            call_count += 1;
            assert_eq!(line, &line_to_add);
        });
        assert_eq!(call_count, i + 1, "Callback call was expected");
    }
}

fn create_log_line(message: &str) -> String {
    let date_time = Local::now().format("%+");
    return format!("{} {}\n", date_time, message);
}

#[test]
fn when_more_than_one_line_is_added_then_update_callback_is_called_for_each_line() {
    let mut file = TestFile::new("auth-monitor-test");
    let mut auth_file_watcher =
        AuthFileWatcher::new(&file.filepath).expect("Error creating AuthFileWatcher");
    expect_no_update_callback_call(&mut auth_file_watcher);

    let mut call_count = 0;
    for i in 0..10 {
        let lines_to_add = AUTH_FAILED_MESSAGES.map(create_log_line);
        for line in &lines_to_add {
            file.write(line)
        }
        auth_file_watcher.update(|line| {
            assert_eq!(line, &lines_to_add[call_count % lines_to_add.len()]);
            call_count += 1;
        });
        assert_eq!(
            call_count,
            (i + 1) * lines_to_add.len(),
            "{} callback calls was expected",
            lines_to_add.len()
        );
    }
}

#[test]
fn when_new_file_was_created_after_old_was_deleted_then_changes_in_new_file_are_monitored() {
    let mut file = TestFile::new("auth-monitor-test");
    let mut auth_file_watcher =
        AuthFileWatcher::new(&file.filepath).expect("Error creating AuthFileWatcher");
    expect_no_update_callback_call(&mut auth_file_watcher);

    file.remove();
    expect_no_update_callback_call(&mut auth_file_watcher);

    file.create();
    expect_no_update_callback_call(&mut auth_file_watcher);

    expect_update_callback_is_called_when_file_is_modified(&mut file, &mut auth_file_watcher);
}

fn expect_no_update_callback_call(auth_file_watcher: &mut AuthFileWatcher) {
    auth_file_watcher.update(|_| {
        panic!("Callback call was not expected");
    });
}

#[test]
fn when_new_file_has_been_created_after_old_was_renamed_then_changes_in_new_file_are_monitored() {
    let mut file = TestFile::new("auth-monitor-test");
    let mut auth_file_watcher =
        AuthFileWatcher::new(&file.filepath).expect("Error creating AuthFileWatcher");
    expect_no_update_callback_call(&mut auth_file_watcher);

    rename_file(&file.filepath, "auth-monitor-test.bak");
    expect_no_update_callback_call(&mut auth_file_watcher);

    file.create();
    expect_no_update_callback_call(&mut auth_file_watcher);

    expect_update_callback_is_called_when_file_is_modified(&mut file, &mut auth_file_watcher);
}

#[test]
fn when_monitored_file_has_been_truncated_then_changes_are_still_monitored() {
    let mut file = TestFile::new("auth-monitor-test");
    let mut auth_file_watcher =
        AuthFileWatcher::new(&file.filepath).expect("Error creating AuthFileWatcher");
    expect_no_update_callback_call(&mut auth_file_watcher);

    file.truncate();
    expect_no_update_callback_call(&mut auth_file_watcher);

    expect_update_callback_is_called_when_file_is_modified(&mut file, &mut auth_file_watcher);
}