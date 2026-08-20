use std::{
    error::Error,
    fmt,
    io::{self, Read},
    path::{Path, PathBuf},
};

use cap_fs_ext::{
    DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _,
    ambient_authority,
};
use cap_std::fs::{Dir, OpenOptions};
use pam_flow::{FlowDefinition, FlowParseError, MAX_FLOW_DOCUMENT_BYTES};

const MAX_FLOW_CATALOG_ENTRIES: usize = 256;
const MAX_FLOW_CATALOG_BYTES: usize = 8 * MAX_FLOW_DOCUMENT_BYTES;

#[derive(Clone, Debug)]
pub(crate) struct CatalogFlow {
    pub(crate) file_name: String,
    pub(crate) source: String,
    pub(crate) normalized: String,
    pub(crate) definition: FlowDefinition,
}

#[derive(Debug)]
pub(crate) struct FlowCatalog {
    entries: Vec<CatalogFlow>,
}

impl FlowCatalog {
    pub(crate) fn load(project_root: &Path) -> Result<Self, FlowCatalogError> {
        Self::load_with_hooks(project_root, |_, _| {}, |_, _| {})
    }

    fn load_with_hooks<F, G>(
        project_root: &Path,
        mut before_open: F,
        mut after_metadata: G,
    ) -> Result<Self, FlowCatalogError>
    where
        F: FnMut(&Dir, &str),
        G: FnMut(&Dir, &str),
    {
        let project_root = project_root
            .canonicalize()
            .map_err(FlowCatalogError::ProjectRoot)?;
        let project_directory = Dir::open_ambient_dir(&project_root, ambient_authority())
            .map_err(FlowCatalogError::ProjectRoot)?;
        let Some(pam_directory) = open_optional_directory(&project_directory, ".pam")? else {
            return Ok(Self {
                entries: Vec::new(),
            });
        };
        let Some(flow_directory) = open_optional_directory(&pam_directory, "flows")? else {
            return Ok(Self {
                entries: Vec::new(),
            });
        };

        let mut entries = Vec::new();
        let mut catalog_bytes = 0_usize;
        let directory = flow_directory
            .entries()
            .map_err(FlowCatalogError::ReadDirectory)?;
        for (index, item) in directory.enumerate() {
            if index >= MAX_FLOW_CATALOG_ENTRIES {
                return Err(FlowCatalogError::TooManyEntries);
            }
            let item = item.map_err(FlowCatalogError::ReadDirectory)?;
            let file_name = item
                .file_name()
                .into_string()
                .map_err(|_| FlowCatalogError::NonUtf8Entry)?;
            let file_type = item.file_type().map_err(FlowCatalogError::ReadEntry)?;
            if file_type.is_symlink() {
                return Err(FlowCatalogError::UnsafeEntry(file_name));
            }
            if file_type.is_dir() {
                continue;
            }
            if !file_type.is_file() {
                return Err(FlowCatalogError::UnsafeEntry(file_name));
            }
            if Path::new(&file_name)
                .extension()
                .and_then(|value| value.to_str())
                != Some("toml")
            {
                continue;
            }
            entries.push(load_catalog_flow(
                &flow_directory,
                file_name,
                &mut catalog_bytes,
                &mut before_open,
                &mut after_metadata,
            )?);
        }
        entries.sort_unstable_by(|left, right| left.file_name.cmp(&right.file_name));
        Ok(Self { entries })
    }

    #[cfg(test)]
    pub(crate) fn load_after_candidate<F>(
        project_root: &Path,
        before_open: F,
    ) -> Result<Self, FlowCatalogError>
    where
        F: FnMut(&Dir, &str),
    {
        Self::load_with_hooks(project_root, before_open, |_, _| {})
    }

    #[cfg(test)]
    pub(crate) fn load_after_metadata<F>(
        project_root: &Path,
        after_metadata: F,
    ) -> Result<Self, FlowCatalogError>
    where
        F: FnMut(&Dir, &str),
    {
        Self::load_with_hooks(project_root, |_, _| {}, after_metadata)
    }

    pub(crate) fn entries(&self) -> &[CatalogFlow] {
        &self.entries
    }

    pub(crate) fn select(&self, selector: &str) -> Result<&CatalogFlow, FlowCatalogError> {
        validate_selector(selector)?;
        let mut matches = self
            .entries
            .iter()
            .filter(|entry| selector == entry.file_name || selector == entry.definition.id());
        let Some(selected) = matches.next() else {
            return Err(FlowCatalogError::NotFound(selector.to_owned()));
        };
        if matches.next().is_some() {
            return Err(FlowCatalogError::Ambiguous(selector.to_owned()));
        }
        Ok(selected)
    }
}

fn load_catalog_flow<F, G>(
    flow_directory: &Dir,
    file_name: String,
    catalog_bytes: &mut usize,
    before_open: &mut F,
    after_metadata: &mut G,
) -> Result<CatalogFlow, FlowCatalogError>
where
    F: FnMut(&Dir, &str),
    G: FnMut(&Dir, &str),
{
    before_open(flow_directory, &file_name);
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = flow_directory
        .open_with(&file_name, &options)
        .map_err(|_| FlowCatalogError::UnsafeEntry(file_name.clone()))?;
    let metadata = file.metadata().map_err(FlowCatalogError::ReadEntry)?;
    if !metadata.is_file() {
        return Err(FlowCatalogError::UnsafeEntry(file_name));
    }
    let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if size > MAX_FLOW_DOCUMENT_BYTES {
        return Err(FlowCatalogError::FileTooLarge(file_name));
    }
    after_metadata(flow_directory, &file_name);
    let mut bytes = Vec::with_capacity(size);
    file.take(u64::try_from(MAX_FLOW_DOCUMENT_BYTES + 1).unwrap())
        .read_to_end(&mut bytes)
        .map_err(FlowCatalogError::ReadEntry)?;
    if bytes.len() > MAX_FLOW_DOCUMENT_BYTES {
        return Err(FlowCatalogError::FileTooLarge(file_name));
    }
    *catalog_bytes = catalog_bytes
        .checked_add(bytes.len())
        .ok_or(FlowCatalogError::CatalogTooLarge)?;
    if *catalog_bytes > MAX_FLOW_CATALOG_BYTES {
        return Err(FlowCatalogError::CatalogTooLarge);
    }
    let source = String::from_utf8(bytes)
        .map_err(|_| FlowCatalogError::NonUtf8Definition(file_name.clone()))?;
    let definition = FlowDefinition::parse_toml(&source).map_err(|error| {
        FlowCatalogError::InvalidDefinition {
            file_name: file_name.clone(),
            reason: sanitized_parse_error(&error),
        }
    })?;
    let expected_file_name = format!("{}.toml", definition.id());
    if file_name != expected_file_name {
        return Err(FlowCatalogError::FileNameMismatch {
            file_name,
            expected_file_name,
        });
    }
    let normalized =
        definition
            .to_normalized_toml()
            .map_err(|_| FlowCatalogError::InvalidDefinition {
                file_name: file_name.clone(),
                reason: "validated definition could not be normalized".to_owned(),
            })?;
    Ok(CatalogFlow {
        file_name,
        source,
        normalized,
        definition,
    })
}

fn sanitized_parse_error(error: &FlowParseError) -> String {
    match error {
        FlowParseError::DocumentTooLarge { .. } => "document exceeds the byte limit".to_owned(),
        FlowParseError::Toml(_) => "TOML syntax is invalid (source omitted)".to_owned(),
        FlowParseError::Validation(error) => {
            let path = error.path();
            if path.len() <= 128
                && path.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'[' | b']' | b'_')
                })
            {
                format!("schema validation failed at {path} (value omitted)")
            } else {
                "schema validation failed (value omitted)".to_owned()
            }
        }
    }
}

fn open_optional_directory(parent: &Dir, name: &str) -> Result<Option<Dir>, FlowCatalogError> {
    match parent.open_dir_nofollow(name) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FlowCatalogError::UnsafeDirectory(PathBuf::from(name))),
    }
}

fn validate_selector(selector: &str) -> Result<(), FlowCatalogError> {
    if selector.is_empty()
        || selector.len() > 256
        || selector == "."
        || selector == ".."
        || selector.contains(['/', '\\'])
        || selector.chars().any(char::is_control)
    {
        return Err(FlowCatalogError::InvalidSelector);
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum FlowCatalogError {
    ProjectRoot(io::Error),
    ReadDirectory(io::Error),
    ReadEntry(io::Error),
    UnsafeDirectory(PathBuf),
    UnsafeEntry(String),
    NonUtf8Entry,
    NonUtf8Definition(String),
    TooManyEntries,
    CatalogTooLarge,
    FileTooLarge(String),
    FileNameMismatch {
        file_name: String,
        expected_file_name: String,
    },
    InvalidDefinition {
        file_name: String,
        reason: String,
    },
    InvalidSelector,
    NotFound(String),
    Ambiguous(String),
}

impl fmt::Display for FlowCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProjectRoot(_) => formatter.write_str("PAM could not resolve the project root."),
            Self::ReadDirectory(_) | Self::ReadEntry(_) => {
                formatter.write_str("PAM could not read the project flow catalog.")
            }
            Self::UnsafeDirectory(path) => write!(
                formatter,
                "Flow catalog directory {} must be a real directory, not a symlink.",
                path.display()
            ),
            Self::UnsafeEntry(name) => {
                write!(
                    formatter,
                    "Flow catalog entry {name} is not a safe regular file."
                )
            }
            Self::NonUtf8Entry => formatter.write_str("Flow catalog contains a non-UTF-8 name."),
            Self::NonUtf8Definition(name) => {
                write!(formatter, "Flow definition {name} is not UTF-8.")
            }
            Self::TooManyEntries => write!(
                formatter,
                "Flow catalog exceeds the {MAX_FLOW_CATALOG_ENTRIES}-entry limit."
            ),
            Self::CatalogTooLarge => formatter.write_str("Flow catalog exceeds its byte limit."),
            Self::FileTooLarge(name) => write!(
                formatter,
                "Flow definition {name} exceeds the {MAX_FLOW_DOCUMENT_BYTES}-byte limit."
            ),
            Self::FileNameMismatch {
                file_name,
                expected_file_name,
            } => write!(
                formatter,
                "Flow definition {file_name} must be named {expected_file_name}."
            ),
            Self::InvalidDefinition { file_name, reason } => {
                write!(
                    formatter,
                    "Flow definition {file_name} is invalid: {reason}"
                )
            }
            Self::InvalidSelector => formatter.write_str(
                "Flow selector must be an exact ID or <id>.toml name with no path traversal.",
            ),
            Self::NotFound(selector) => write!(formatter, "Flow {selector} was not found."),
            Self::Ambiguous(selector) => write!(
                formatter,
                "Flow selector {selector} matches more than one definition."
            ),
        }
    }
}

impl Error for FlowCatalogError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ProjectRoot(error) | Self::ReadDirectory(error) | Self::ReadEntry(error) => {
                Some(error)
            }
            _ => None,
        }
    }
}
