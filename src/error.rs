use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnalysisError {
    #[error("Rules load error: {0}")]
    RulesLoad(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AnalysisError>;

impl AnalysisError {
    pub fn message(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}
