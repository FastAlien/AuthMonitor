use chrono::Local;
use std::env::temp_dir;
use std::fs::{remove_file, rename, File};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::auth_message_parser::DATE_FORMAT_ISO_8601;

pub const AUTH_FAILED_TEST_MESSAGES: [&str; 6] = [
    "workstation sudo: pam_unix(sudo:auth): authentication failure; logname=john uid=1000 euid=0 tty=/dev/pts/7 ruser=john rhost=  user=john",
    "workstation kscreenlocker_greet: pam_unix(kde:auth): authentication failure; logname= uid=1000 euid=1000 tty= ruser= rhost=  user=john",
    "workstation unix_chkpwd[222793]: password check failed for user (john)",
    "workstation kscreenlocker_greet: pam_unix(kde:auth): authentication failure; logname=john uid=1000 euid=1000 tty= ruser= rhost=  user=john",
    "workstation kscreenlocker_greet: pam_unix(kde-fingerprint:auth): authentication failure; logname=john uid=1000 euid=1000 tty= ruser= rhost=  user=john",
    "workstation kscreenlocker_greet: pam_unix(kde-smartcard:auth): authentication failure; logname=john uid=1000 euid=1000 tty= ruser= rhost=  user=john",
];

const OTHER_TEST_MESSAGES: [&str; 10] = [
    "workstation dbus-daemon[1988]: [system] Failed to activate service 'org.bluez': timed out (service_start_timeout=25000ms)",
    "workstation CRON[9419]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
    "workstation CRON[9419]: pam_unix(cron:session): session closed for user root",
    "workstation PackageKit: uid 1000 is trying to obtain org.freedesktop.packagekit.system-sources-refresh auth (only_trusted:0)",
    "workstation kscreenlocker_greet: pam_unix(kde-fingerprint:auth): unexpected response from failed conversation function",
    "workstation kscreenlocker_greet: pam_unix(kde-fingerprint:auth): conversation failed",
    "workstation kscreenlocker_greet: pam_unix(kde-fingerprint:auth): auth could not identify password for [john]",
    "workstation kscreenlocker_greet: pam_unix(kde-smartcard:auth): unexpected response from failed conversation function",
    "workstation kscreenlocker_greet: pam_unix(kde-smartcard:auth): conversation failed",
    "workstation kscreenlocker_greet: pam_unix(kde-smartcard:auth): auth could not identify password for [john]",
];

pub struct TestFile {
    path: String,
    file: File,
}

impl TestFile {
    pub fn not_empty() -> TestFile {
        let mut file = Self::empty();
        file.write_other_messages(5);
        file.write_auth_failed_messages(5);
        return file;
    }

    pub fn empty() -> TestFile {
        let filename = format!(
            "auth-monitor-test-{}-{}.log",
            Self::next_id(),
            Local::now().timestamp_micros()
        );
        let path_buffer = temp_dir().join(filename);
        let path = path_buffer.to_str().expect("Error creating file path");
        return Self::new(path);
    }

    fn next_id() -> usize {
        static ID: AtomicUsize = AtomicUsize::new(1);
        return ID.fetch_add(1, Ordering::Relaxed);
    }

    pub fn new(path: &str) -> TestFile {
        println!("Creating test file: {}", path);
        return TestFile {
            path: String::from(path),
            file: File::create(path).expect("Error creating test file"),
        };
    }

    pub fn path(&self) -> &str {
        return &self.path;
    }

    pub fn create(&mut self) {
        println!("Creating test file: {}", &self.path);
        self.file = File::create(&self.path).expect("Error creating test file");
    }

    pub fn write_auth_failed_messages(&mut self, count: usize) {
        for i in 0usize..count {
            self.write_auth_failed_message(i);
        }
    }

    pub fn write_auth_failed_message(&mut self, index: usize) {
        let message_index = index % AUTH_FAILED_TEST_MESSAGES.len();
        let message = AUTH_FAILED_TEST_MESSAGES[message_index];
        self.write_log_message(message);
    }

    fn write_log_message(&mut self, message: &str) {
        let date_time = Local::now().format(DATE_FORMAT_ISO_8601);
        let line = format!("{} {}\n", date_time, message);
        self.write(&line);
    }

    fn write(&mut self, message: &str) {
        print!("Writing line: {}", message);
        let bytes_to_add = message.as_bytes();
        let bytes_written = self
            .file
            .write(bytes_to_add)
            .expect("Error writing to file");
        assert_eq!(bytes_written, bytes_to_add.len());
    }

    pub fn write_other_messages(&mut self, count: usize) {
        for i in 0usize..count {
            self.write_other_message(i);
        }
    }

    pub fn write_other_message(&mut self, index: usize) {
        let message_index = index % OTHER_TEST_MESSAGES.len();
        let message = OTHER_TEST_MESSAGES[message_index];
        self.write_log_message(message);
    }

    pub fn truncate(&mut self) {
        println!("Truncating test file: {}", self.path);
        self.file.set_len(0).expect("Error truncating file");
    }

    pub fn rename(&mut self, new_path: &str) {
        println!("Renaming test file {} to {}", self.path, new_path);
        rename(&self.path, new_path).expect("Unable to rename test file");
        self.path = String::from(new_path);
    }

    pub fn remove(&mut self) {
        println!("Removing test file: {}", self.path);
        remove_file(&self.path).expect("Unable to remove test file");
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        self.remove();
    }
}
