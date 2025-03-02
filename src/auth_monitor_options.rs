use std::fmt::{Display, Formatter};

#[derive(Copy, Clone)]
pub struct AuthMonitorOptions {
    pub max_failed_attempts: i32,
    pub reset_after_seconds: i32,
    pub ignore_following_auth_fails_ms: i32,
}

impl Default for AuthMonitorOptions {
    fn default() -> Self {
        return AuthMonitorOptions {
            max_failed_attempts: 5,
            reset_after_seconds: 1800,
            ignore_following_auth_fails_ms: 0,
        };
    }
}

impl Display for AuthMonitorOptions {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        return write!(
            formatter,
            "max-failed-attempts={}, reset-after-seconds={}, ignore-following-auth-fails-ms={}",
            self.max_failed_attempts, self.reset_after_seconds, self.ignore_following_auth_fails_ms
        );
    }
}
