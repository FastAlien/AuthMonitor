use std::env::temp_dir;
use std::fs::{remove_file, rename, File};
use std::io::Write;
use std::path::Path;

use chrono::Local;

pub struct TestFile {
    pub filepath: String,
    file: File,
}

impl TestFile {
    pub fn new(prefix: &str) -> TestFile {
        let filename = format!("{}-{}.log", prefix, Local::now().timestamp_micros());
        let filepath_buffer = temp_dir().join(filename);
        let filepath = filepath_buffer.to_str().expect("Error creating filepath");
        println!("Creating test file: {}", filepath);
        return TestFile {
            filepath: String::from(filepath),
            file: File::create(filepath).expect("Error creating test file"),
        };
    }

    pub fn create(&mut self) {
        println!("Creating test file: {}", &self.filepath);
        self.file = File::create(&self.filepath).expect("Error creating test file");
    }

    pub fn write(&mut self, message: &str) {
        let bytes_to_add = message.as_bytes();
        let bytes_written = self
            .file
            .write(bytes_to_add)
            .expect("Error writing to file");
        assert_eq!(bytes_written, bytes_to_add.len());
    }

    pub fn truncate(&mut self) {
        println!("Truncating test file: {}", self.filepath);
        self.file.set_len(0).expect("Error truncating file");
    }

    pub fn remove(&mut self) {
        println!("Removing test file: {}", self.filepath);
        remove_file(&self.filepath).expect("Unable to remove test file");
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        self.remove();
    }
}

pub fn rename_file(filepath: &str, new_filename: &str) {
    println!("Renaming test file {} to {}", filepath, new_filename);
    let new_path = Path::new(&filepath)
        .parent()
        .expect("Unable to get directory")
        .join(new_filename);
    let new_filepath = new_path.to_str().expect("Unable to build file path");
    rename(filepath, new_filepath).expect("Unable to rename test file");
}