use std::error::Error;

use crate::assert_error;
use crate::auth_monitor_options::AuthMonitorOptions;
use crate::auth_monitor_params::{
    AuthMonitorParams, IGNORE_SUBSEQUENT_FAILS_MS_OPTION, MAX_FAILED_ATTEMPTS_OPTION,
    RESET_AFTER_SECONDS_OPTION,
};

const FILEPATH: &str = "/var/log/auth.log";
const ALL_OPTIONS: [&str; 3] = [
    MAX_FAILED_ATTEMPTS_OPTION,
    RESET_AFTER_SECONDS_OPTION,
    IGNORE_SUBSEQUENT_FAILS_MS_OPTION,
];

const ZERO_VALUE_ALLOWED_OPTIONS: [&str; 1] = [IGNORE_SUBSEQUENT_FAILS_MS_OPTION];

const ZERO_VALUE_NOT_ALLOWED_OPTIONS: [&str; 2] =
    [MAX_FAILED_ATTEMPTS_OPTION, RESET_AFTER_SECONDS_OPTION];

type AuthMonitorResult = Result<AuthMonitorParams, Box<dyn Error>>;

#[test]
fn when_parsing_no_arguments_then_return_file_not_specified_error() {
    expect_file_not_specified_error(AuthMonitorParams::from_arguments(&[]));
}

fn expect_file_not_specified_error(result: AuthMonitorResult) {
    assert_error!(result, "File path not specified");
}

#[test]
fn when_parsing_one_option_without_filepath_then_return_file_not_specified_error() {
    for option in ALL_OPTIONS.map(format_example_option) {
        let arguments = [option];
        expect_file_not_specified_error(AuthMonitorParams::from_arguments(&arguments));
    }
}

#[test]
fn when_parsing_multiple_options_without_filepath_then_return_file_not_specified_error() {
    let arguments = ALL_OPTIONS.map(format_example_option);
    expect_file_not_specified_error(AuthMonitorParams::from_arguments(&arguments));
}

fn format_example_option(option: &str) -> String {
    return format!("--{}={}", option, 10);
}

#[test]
fn when_parsing_filepath_passed_more_than_once_then_return_file_path_specified_more_than_once_error(
) {
    let mut arguments = vec![String::from(FILEPATH), String::from(FILEPATH)];
    expect_file_path_specified_more_than_once_error(AuthMonitorParams::from_arguments(&arguments));

    let options = ALL_OPTIONS.map(format_example_option);
    arguments.extend_from_slice(&options);
    expect_file_path_specified_more_than_once_error(AuthMonitorParams::from_arguments(&arguments));
}

fn expect_file_path_specified_more_than_once_error(result: AuthMonitorResult) {
    assert_error!(result, "File path specified more than once");
}

#[test]
fn when_parsing_filepath_without_options_then_return_struct_with_default_values() {
    let arguments = [String::from(FILEPATH)];
    let expected = AuthMonitorParams {
        filepath: String::from(FILEPATH),
        ..AuthMonitorParams::default()
    };
    expect_equals(AuthMonitorParams::from_arguments(&arguments), &expected);
}

fn expect_equals(result: Result<AuthMonitorParams, Box<dyn Error>>, expected: &AuthMonitorParams) {
    let params = result.unwrap();
    assert_eq!(
        params.filepath, expected.filepath,
        "File path does not match"
    );
    assert_eq!(
        params.options.max_failed_attempts, expected.options.max_failed_attempts,
        "Max failed attempts does not match"
    );
    assert_eq!(
        params.options.reset_after_seconds, expected.options.reset_after_seconds,
        "Reset after seconds does not match"
    );
}

#[test]
fn when_parsing_filepath_with_one_option_with_correct_value_then_return_params_with_that_value() {
    let default_params = AuthMonitorParams::default();
    for option in ALL_OPTIONS {
        let value = 30;
        let option_argument = format!("--{}={}", option, value);
        let arguments = [String::from(FILEPATH), option_argument];
        let max_failed_attempts = match option == MAX_FAILED_ATTEMPTS_OPTION {
            true => value,
            false => default_params.options.max_failed_attempts,
        };
        let reset_after_seconds = match option == RESET_AFTER_SECONDS_OPTION {
            true => value,
            false => default_params.options.reset_after_seconds,
        };
        let ignore_subsequent_fails_ms = match option == IGNORE_SUBSEQUENT_FAILS_MS_OPTION {
            true => value,
            false => default_params.options.ignore_subsequent_fails_ms,
        };
        let expected = AuthMonitorParams {
            filepath: String::from(FILEPATH),
            options: AuthMonitorOptions {
                max_failed_attempts,
                reset_after_seconds,
                ignore_subsequent_fails_ms,
            },
        };
        expect_equals(AuthMonitorParams::from_arguments(&arguments), &expected);
    }
}

#[test]
fn when_parsing_option_without_value_then_return_missing_option_value_error() {
    for option in ALL_OPTIONS {
        let option_arguments = [format!("--{}", option), format!("--{}=", option)];
        for option_argument in option_arguments {
            let arguments = [String::from(FILEPATH), option_argument];
            let expected = format!("Missing value for option --{}", option);
            assert_error!(AuthMonitorParams::from_arguments(&arguments), expected);
        }
    }
}

#[test]
fn when_parsing_option_with_invalid_value_then_return_invalid_option_value_error() {
    for option in ALL_OPTIONS {
        let values = ["test", "3a", "--", "b23", "12@"];
        for value in values {
            let option_argument = format!("--{}={}", option, value);
            let arguments = [String::from(FILEPATH), option_argument];
            let expected = format!("\"{}\" is not a valid value for option --{}", value, option);
            assert_error!(AuthMonitorParams::from_arguments(&arguments), expected);
        }
    }
}

#[test]
fn when_parsing_option_with_no_value_then_return_no_value_error() {
    for option in ALL_OPTIONS {
        let option_argument = format!("--{}=", option);
        let arguments = [String::from(FILEPATH), option_argument];
        let expected = format!("Missing value for option --{}", option);
        assert_error!(AuthMonitorParams::from_arguments(&arguments), expected);
    }
}

#[test]
fn when_parsing_option_with_out_of_range_value_then_return_value_out_of_range_error() {
    let zero_not_allowed_invalid_values = [0, -1, -1024, i32::MIN];
    for option in ZERO_VALUE_NOT_ALLOWED_OPTIONS {
        for value in zero_not_allowed_invalid_values {
            let option_argument = format!("--{}={}", option, value);
            let arguments = [String::from(FILEPATH), option_argument];
            let expected = format!("{} must be greater than 0", option);
            assert_error!(AuthMonitorParams::from_arguments(&arguments), expected);
        }
    }

    let zero_allowed_invalid_values = [-1, -1024, i32::MIN];
    for option in ZERO_VALUE_ALLOWED_OPTIONS {
        for value in zero_allowed_invalid_values {
            let option_argument = format!("--{}={}", option, value);
            let arguments = [String::from(FILEPATH), option_argument];
            let expected = format!("{} must be greater than or equal 0", option);
            assert_error!(AuthMonitorParams::from_arguments(&arguments), expected);
        }
    }
}

#[test]
fn when_parsing_filename_and_multiple_options_then_return_params_with_parsed_values() {
    let max_failed_attempts = 10;
    let reset_after_seconds = 3600;
    let ignore_subsequent_fails_ms = 350;
    let arguments = [
        String::from(FILEPATH),
        format!("--{}={}", MAX_FAILED_ATTEMPTS_OPTION, max_failed_attempts),
        format!("--{}={}", RESET_AFTER_SECONDS_OPTION, reset_after_seconds),
        format!(
            "--{}={}",
            IGNORE_SUBSEQUENT_FAILS_MS_OPTION, ignore_subsequent_fails_ms
        ),
    ];
    let expected = AuthMonitorParams {
        filepath: String::from(FILEPATH),
        options: AuthMonitorOptions {
            max_failed_attempts,
            reset_after_seconds,
            ignore_subsequent_fails_ms,
        },
    };
    expect_equals(AuthMonitorParams::from_arguments(&arguments), &expected);
}

#[test]
fn when_parsing_unknown_option_then_return_unknown_option_error() {
    let unknown_options = [
        "--no-value",
        "--u=",
        "--unknown=10",
        "--unknown-option=test",
    ];
    for option in unknown_options {
        let arguments = [String::from(FILEPATH), String::from(option)];
        let expected = format!("Unknown option {}", option);
        assert_error!(AuthMonitorParams::from_arguments(&arguments), expected)
    }
}
