use chrono::DateTime;

pub const DATE_FORMAT_ISO_8601: &str = "%Y-%m-%dT%H:%M:%S.%6f%:z";

pub struct AuthMessageParser {
    patterns: Vec<AuthFailedMessagePattern>,
}

struct AuthFailedMessagePattern {
    prefix: String,
    message: String,
}

impl AuthMessageParser {
    pub fn new() -> AuthMessageParser {
        let pam_message = AuthFailedMessagePattern {
            prefix: String::from("pam_unix"),
            message: String::from("authentication failure"),
        };
        let unix_chkpwd_message = AuthFailedMessagePattern {
            prefix: String::from("unix_chkpwd"),
            message: String::from("password check failed"),
        };
        return AuthMessageParser {
            patterns: vec![pam_message, unix_chkpwd_message],
        };
    }

    pub fn is_auth_failed_message(&self, message: &str) -> bool {
        for pattern in &self.patterns {
            match message.find(&pattern.prefix) {
                None => {}
                Some(prefix_position) => {
                    let message_after_prefix = &message[prefix_position + pattern.prefix.len()..];
                    if message_after_prefix.contains(&pattern.message) {
                        return true;
                    }
                }
            };
        }
        return false;
    }

    pub fn get_message_timestamp_millis(&self, message: &str) -> i64 {
        let date_time_str = message.get(0..32).unwrap_or("");
        return match DateTime::parse_from_str(date_time_str, DATE_FORMAT_ISO_8601) {
            Ok(date_time) => date_time.timestamp_millis(),
            Err(_) => 0,
        };
    }
}

#[cfg(test)]
#[path = "./auth_message_parser_tests.rs"]
mod tests;
