use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml parse error at line {line}: {message}")]
    Parse { line: u32, message: String },

    #[error("validation failed: {0:#?}")]
    Validation(Vec<String>),

    #[error("yaml patch failed: {0}")]
    Patch(String),

    #[error("merge failed: {0}")]
    Merge(String),
}

/// serde_norway 错误转带行号的解析错误。
pub fn from_yaml(err: serde_norway::Error) -> ConfigError {
    let line = err
        .location()
        .map(|loc| loc.line() as u32)
        .unwrap_or(0)
        .max(1);
    ConfigError::Parse {
        line,
        message: err.to_string(),
    }
}
