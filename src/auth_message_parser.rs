use chrono::DateTime;

const DATE_FORMAT_ISO_8601_WITH_MS: &str = "%Y-%m-%dT%H:%M:%S%.f%:z";

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
        let datetime_str = message.get(0..35).unwrap_or("");
        return match DateTime::parse_from_str(datetime_str, DATE_FORMAT_ISO_8601_WITH_MS) {
            Ok(datetime) => datetime.timestamp_millis(),
            Err(_) => 0,
        };
    }
}

#[cfg(test)]
#[path = "./auth_message_parser_tests.rs"]
mod tests;
