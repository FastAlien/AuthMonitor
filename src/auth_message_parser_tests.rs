use chrono::{Duration, Local};
use std::ops::Sub;

use crate::auth_message_parser::{AuthMessageParser, DATE_FORMAT_ISO_8601};
use crate::test_utils::test_file::AUTH_FAILED_TEST_MESSAGES;

#[test]
fn when_message_is_auth_failed_message_then_returns_true() {
    let parser = AuthMessageParser::new();
    for message in AUTH_FAILED_TEST_MESSAGES {
        assert!(parser.is_auth_failed_message(message));
    }
}

#[test]
fn when_message_is_not_auth_failed_message_then_returns_false() {
    let messages = "2024-02-10T14:26:03.323862+01:00 workstation systemd-logind[2089]: The system will power off now!
2024-02-10T14:26:03.341715+01:00 workstation systemd-logind[2089]: System is powering down.
2024-02-10T14:27:14.249214+01:00 workstation polkitd[2009]: Loading rules from directory /etc/polkit-1/rules.d
2024-02-10T14:27:14.249443+01:00 workstation polkitd[2009]: Loading rules from directory /usr/share/polkit-1/rules.d
2024-02-10T14:27:14.251498+01:00 workstation systemd-logind[2025]: New seat seat0.
2024-02-10T14:27:14.253400+01:00 workstation systemd-logind[2025]: Watching system buttons on /dev/input/event1 (Power Button)
2024-02-10T14:27:14.253431+01:00 workstation systemd-logind[2025]: Watching system buttons on /dev/input/event0 (Power Button)
2024-02-10T14:27:14.253502+01:00 workstation polkitd[2009]: Finished loading, compiling and executing 12 rules
2024-02-10T14:27:14.253651+01:00 workstation systemd-logind[2025]: Watching system buttons on /dev/input/event4 (INSTANT USB GAMING MOUSE  Keyboard)
2024-02-10T14:27:14.253697+01:00 workstation systemd-logind[2025]: Watching system buttons on /dev/input/event5 (SONiX USB Keyboard)
2024-02-10T14:27:14.253741+01:00 workstation systemd-logind[2025]: Watching system buttons on /dev/input/event6 (SONiX USB Keyboard Consumer Control)
2024-02-10T14:27:14.253782+01:00 workstation systemd-logind[2025]: Watching system buttons on /dev/input/event7 (SONiX USB Keyboard System Control)
2024-02-10T14:27:14.253938+01:00 workstation polkitd[2009]: Acquired the name org.freedesktop.PolicyKit1 on the system bus
2024-02-10T14:27:15.037317+01:00 workstation sshd[2423]: Server listening on :: port 22.
2024-02-10T14:27:16.721168+01:00 workstation sddm-helper: pam_unix(sddm-greeter:session): session opened for user sddm(uid=119) by (uid=0)
2024-02-10T14:27:16.765872+01:00 workstation systemd-logind[2025]: New session 1 of user sddm.
2024-02-10T14:27:16.781631+01:00 workstation (systemd): pam_unix(systemd-user:session): session opened for user sddm(uid=119) by (uid=0)
2024-02-10T14:27:21.836422+01:00 workstation sddm-helper: gkr-pam: unable to locate daemon control file
2024-02-10T14:27:21.836501+01:00 workstation sddm-helper: gkr-pam: stashed password to try later in open session
2024-02-10T14:27:21.836557+01:00 workstation sddm-helper: pam_kwallet5(sddm:auth): pam_kwallet5: pam_sm_authenticate
2024-02-10T14:27:21.837901+01:00 workstation sddm-helper: pam_kwallet5(sddm:setcred): pam_kwallet5: pam_sm_setcred
2024-02-10T14:27:21.840142+01:00 workstation sddm-helper: pam_unix(sddm:session): session opened for user john(uid=1000) by (uid=0)
2024-02-10T14:27:21.876338+01:00 workstation systemd-logind[2025]: New session 3 of user john.
2024-02-10T14:27:21.889222+01:00 workstation (systemd): pam_unix(systemd-user:session): session opened for user john(uid=1000) by (uid=0)
2024-02-10T14:27:21.910749+01:00 workstation sddm-helper: pam_unix(sddm-greeter:session): session closed for user sddm
2024-02-10T14:27:21.912739+01:00 workstation systemd-logind[2025]: Session 1 logged out. Waiting for processes to exit.
2024-02-10T14:27:21.913276+01:00 workstation systemd-logind[2025]: Removed session 1.
2024-02-10T14:27:22.129578+01:00 workstation sddm-helper: gkr-pam: unlocked login keyring
2024-02-10T14:27:22.129661+01:00 workstation sddm-helper: pam_kwallet5(sddm:session): pam_kwallet5: pam_sm_open_session
2024-02-10T14:27:22.129907+01:00 workstation sddm-helper: pam_env(sddm:session): deprecated reading of user environment enabled
2024-02-10T14:27:25.150915+01:00 workstation polkitd[2009]: Registered Authentication Agent for unix-session:3 (system bus name :1.74 [/usr/lib/x86_64-linux-gnu/libexec/polkit-kde-authentication-agent-1], object path /org/kde/PolicyKit1/AuthenticationAgent, locale pl_PL.UTF-8)
2024-02-10T14:27:51.038430+01:00 workstation dbus-daemon[1988]: [system] Failed to activate service 'org.bluez': timed out (service_start_timeout=25000ms)
2024-02-10T14:30:01.170069+01:00 workstation CRON[9419]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
2024-02-10T14:30:01.172454+01:00 workstation CRON[9419]: pam_unix(cron:session): session closed for user root
2024-02-10T14:32:25.960982+01:00 workstation PackageKit: uid 1000 is trying to obtain org.freedesktop.packagekit.system-sources-refresh auth (only_trusted:0)
2024-02-10T14:32:25.990094+01:00 workstation PackageKit: uid 1000 obtained auth for org.freedesktop.packagekit.system-sources-refresh
2024-02-10T14:34:24.371421+01:00 workstation sudo:   john : TTY=pts/3 ; PWD=/home/john ; USER=root ; COMMAND=/usr/bin/ls
2024-02-10T14:34:24.372326+01:00 workstation sudo: pam_unix(sudo:session): session opened for user root(uid=0) by john(uid=1000)
2024-02-10T14:34:24.374716+01:00 workstation sudo: pam_unix(sudo:session): session closed for user root";
    let parser = AuthMessageParser::new();
    for message in messages.split('\n') {
        assert!(!parser.is_auth_failed_message(message));
    }
}

#[test]
fn when_parsing_message_with_incorrect_date_time_format_then_return_0() {
    let messages = "2024-02-10T14:26:03.323862+01:0 workstation systemd-logind[2089]: The system will power off now!
2024-02-10T14:26:03.341715 workstation systemd-logind[2089]: System is powering down.
2024-02-10T14:34:24.37471+01:00 workstation sudo: pam_unix(sudo:session): session closed for user root
workstation sudo: pam_unix(sudo:session): session closed for user root";
    let parser = AuthMessageParser::new();
    for message in messages.split('\n') {
        let message_timestamp = parser.get_message_timestamp_millis(message);
        assert_eq!(message_timestamp, 0);
    }
}

#[test]
fn when_parsing_message_with_correct_date_time_format_then_return_timestamp_in_millis() {
    let now = Local::now();
    let date_times = [
        now,
        now.sub(Duration::milliseconds(123)),
        now.sub(Duration::seconds(1234)),
        now.sub(Duration::minutes(1234)),
        now.sub(Duration::hours(4)),
    ];
    let parser = AuthMessageParser::new();
    for date_time in date_times {
        let formatted_date_time = date_time.format(DATE_FORMAT_ISO_8601);
        let message = format!("{} {}", formatted_date_time, AUTH_FAILED_TEST_MESSAGES[0]);
        let message_timestamp = parser.get_message_timestamp_millis(&message);
        let expected_timestamp = date_time.timestamp_millis();
        assert_eq!(message_timestamp, expected_timestamp);
    }
}
