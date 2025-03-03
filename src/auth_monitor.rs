use chrono::Local;
use std::error::Error;

use crate::auth_file_watcher::AuthFileWatcher;
use crate::auth_message_parser::AuthMessageParser;
use crate::auth_monitor_options::AuthMonitorOptions;
use crate::auth_monitor_params::AuthMonitorParams;

pub struct AuthMonitor {
    failed_attempts: i32,
    options: AuthMonitorOptions,
    file_watcher: AuthFileWatcher,
    auth_message_parser: AuthMessageParser,
    last_failed_auth_timestamp: i64,
}

impl AuthMonitor {
    pub fn new(params: AuthMonitorParams) -> Result<AuthMonitor, Box<dyn Error>> {
        params.validate()?;
        return Ok(AuthMonitor {
            failed_attempts: 0,
            options: params.options,
            file_watcher: AuthFileWatcher::new(&params.filepath)?,
            auth_message_parser: AuthMessageParser::new(),
            last_failed_auth_timestamp: 0,
        });
    }

    pub fn update(&mut self, on_max_failed_attempts: impl FnOnce()) {
        if self.should_reset_failed_attempts() {
            self.reset_failed_attempts();
        }

        let mut failed_attempts = 0;

        self.file_watcher.update(|line| {
            if !self.auth_message_parser.is_auth_failed_message(line) {
                return;
            }
            print!("Auth failed message: {}", line);
            let mut auth_failed_timestamp =
                self.auth_message_parser.get_message_timestamp_millis(line);
            if auth_failed_timestamp == 0 {
                auth_failed_timestamp = Local::now().timestamp_millis();
            }
            if self.options.ignore_subsequent_fails_ms > 0 {
                let millis_since_last_failed_auth =
                    auth_failed_timestamp - self.last_failed_auth_timestamp;
                if millis_since_last_failed_auth <= self.options.ignore_subsequent_fails_ms as i64 {
                    println!(
                        "Auth fail ignored ({} ms since last)",
                        millis_since_last_failed_auth
                    );
                    return;
                }
            }
            self.last_failed_auth_timestamp = auth_failed_timestamp;
            failed_attempts += 1;
        });

        if failed_attempts > 0 {
            self.increase_failed_attempts(failed_attempts, on_max_failed_attempts);
        }
    }

    fn should_reset_failed_attempts(&self) -> bool {
        if self.last_failed_auth_timestamp == 0 {
            return false;
        }
        if self.failed_attempts <= 0 || self.failed_attempts >= self.options.max_failed_attempts {
            return false;
        }
        let millis_since_last_auth_fail =
            Local::now().timestamp_millis() - self.last_failed_auth_timestamp;
        let reset_after_millis = self.options.reset_after_seconds as i64 * 1000;
        return millis_since_last_auth_fail > reset_after_millis;
    }

    fn reset_failed_attempts(&mut self) {
        println!("Resetting failed attempts");
        self.failed_attempts = 0;
        self.last_failed_auth_timestamp = 0;
    }

    fn increase_failed_attempts(
        &mut self,
        failed_attempts: i32,
        on_max_failed_attempts: impl FnOnce(),
    ) {
        self.failed_attempts += failed_attempts;
        println!("Authentication failed {} time(s)", self.failed_attempts);
        if self.failed_attempts >= self.options.max_failed_attempts {
            println!("Authentication fail limit reached, shutting down");
            on_max_failed_attempts();
        }
    }
}

#[cfg(test)]
#[path = "./auth_monitor_tests.rs"]
mod tests;
