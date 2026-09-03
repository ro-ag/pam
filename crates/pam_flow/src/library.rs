//! The global flow library: `<base>/flows/<id>.yaml` over the builtins.
//!
//! Flows are global on purpose — a flow is a recipe a human keeps, not
//! something a repository can hand the agent. The directory holds one file
//! per flow, named after its id; anything else in there is ignored. A
//! library file with a builtin's id shadows it, and deleting that file
//! reveals the builtin again.
//!
//! Listing never fails because one file is broken: an unreadable flow comes
//! back as an [`Entry`] whose `parsed` is the validation error, so the GUI
//! can show the file and say what is wrong with it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::builtin::{builtin, builtin_yaml};
use crate::schema::Flow;
use crate::validate::{FlowError, MAX_ID_BYTES, MAX_LIBRARY_ENTRIES, parse};

/// Where a flow came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Shipped inside pam.
    Builtin,
    /// A file in the library directory.
    Library,
}

impl Source {
    /// The wire name, `"builtin"` or `"library"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Library => "library",
        }
    }
}

/// One flow as the library sees it: its text, where it came from, and
/// either the validated flow or the reason it is unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The flow id.
    pub id: String,
    /// Builtin or library file.
    pub source: Source,
    /// The file, when the flow came from one.
    pub path: Option<PathBuf>,
    /// The exact YAML text.
    pub yaml: String,
    /// The validated flow, or why it was refused.
    pub parsed: Result<Flow, FlowError>,
}

/// The flow library directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Library {
    dir: PathBuf,
}

impl Library {
    /// Opens the library at `dir`. The directory need not exist yet; it is
    /// created on the first [`save`](Self::save).
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// The directory this library reads and writes.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Every flow, sorted by id, library files shadowing builtins.
    ///
    /// # Errors
    ///
    /// [`FlowError::Io`] when the directory cannot be read, and
    /// [`FlowError::Invalid`] when it holds more than
    /// [`MAX_LIBRARY_ENTRIES`] flow files.
    pub fn list(&self) -> Result<Vec<Entry>, FlowError> {
        let mut entries: Vec<Entry> = builtin()
            .iter()
            .map(|flow| entry(flow.id, Source::Builtin, None, flow.yaml.to_string()))
            .collect();

        let mut files = self.files()?;
        if files.len() > MAX_LIBRARY_ENTRIES {
            return Err(FlowError::Invalid {
                path: "library".to_string(),
                message: format!(
                    "the flow library holds {} files; the limit is {MAX_LIBRARY_ENTRIES}",
                    files.len()
                ),
            });
        }
        files.sort();
        for (id, path) in files {
            let yaml = read(&path)?;
            let found = entry(&id, Source::Library, Some(path), yaml);
            match entries.iter_mut().find(|existing| existing.id == id) {
                Some(existing) => *existing = found,
                None => entries.push(found),
            }
        }
        entries.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(entries)
    }

    /// One flow by id — the library file if there is one, else the builtin.
    ///
    /// # Errors
    ///
    /// [`FlowError::Io`] when the file cannot be read.
    pub fn get(&self, id: &str) -> Result<Option<Entry>, FlowError> {
        if !is_flow_id(id) {
            return Ok(None);
        }
        let path = self.path_for(id);
        if path.is_file() {
            let yaml = read(&path)?;
            return Ok(Some(entry(id, Source::Library, Some(path), yaml)));
        }
        Ok(builtin_yaml(id).map(|yaml| entry(id, Source::Builtin, None, yaml.to_string())))
    }

    /// Validates `yaml` and writes it to `<dir>/<id>.yaml`.
    ///
    /// The write is atomic: the text lands in a temporary file next to the
    /// target and is renamed over it, so a reader never sees half a flow.
    /// Nothing is written when the flow does not validate.
    ///
    /// # Errors
    ///
    /// Whatever [`parse`] refuses, [`FlowError::Invalid`] when the flow's
    /// own id is not `id` or the library is full, and [`FlowError::Io`] when
    /// the directory cannot be written.
    pub fn save(&self, id: &str, yaml: &str) -> Result<Entry, FlowError> {
        if !is_flow_id(id) {
            return Err(FlowError::Invalid {
                path: "id".to_string(),
                message: format!(
                    "`{id}` is not a flow id: lower-case letters, digits and `-`, 1 to {MAX_ID_BYTES} bytes"
                ),
            });
        }
        let flow = parse(yaml)?;
        if flow.id != id {
            return Err(FlowError::Invalid {
                path: "id".to_string(),
                message: format!(
                    "the flow declares id `{}` but is being saved as `{id}`; they must match",
                    flow.id
                ),
            });
        }

        let path = self.path_for(id);
        if !path.is_file() && self.files()?.len() >= MAX_LIBRARY_ENTRIES {
            return Err(FlowError::Invalid {
                path: "library".to_string(),
                message: format!(
                    "the flow library already holds {MAX_LIBRARY_ENTRIES} flows; delete one first"
                ),
            });
        }

        fs::create_dir_all(&self.dir).map_err(|error| io_error(&self.dir, &error))?;
        let temporary = self
            .dir
            .join(format!("{id}.yaml.tmp-{}", std::process::id()));
        if let Err(error) = fs::write(&temporary, yaml) {
            drop(fs::remove_file(&temporary));
            return Err(io_error(&temporary, &error));
        }
        if let Err(error) = fs::rename(&temporary, &path) {
            drop(fs::remove_file(&temporary));
            return Err(io_error(&path, &error));
        }

        Ok(Entry {
            id: id.to_string(),
            source: Source::Library,
            path: Some(path),
            yaml: yaml.to_string(),
            parsed: Ok(flow),
        })
    }

    /// Removes a library file, answering whether a builtin is now visible
    /// again.
    ///
    /// # Errors
    ///
    /// [`FlowError::Invalid`] when no library file carries that id — a
    /// builtin without a shadow is not the library's to delete — and
    /// [`FlowError::Io`] when the file cannot be removed.
    pub fn delete(&self, id: &str) -> Result<bool, FlowError> {
        let path = self.path_for(id);
        if !is_flow_id(id) || !path.is_file() {
            return Err(FlowError::Invalid {
                path: "id".to_string(),
                message: format!("no library flow named `{id}`"),
            });
        }
        fs::remove_file(&path).map_err(|error| io_error(&path, &error))?;
        Ok(builtin_yaml(id).is_some())
    }

    fn path_for(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.yaml"))
    }

    /// Every `<id>.yaml` in the directory, paired with its id. Anything
    /// else — other extensions, directories, names that are not flow ids —
    /// is ignored.
    fn files(&self) -> Result<Vec<(String, PathBuf)>, FlowError> {
        let listing = match fs::read_dir(&self.dir) {
            Ok(listing) => listing,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io_error(&self.dir, &error)),
        };
        let mut files = Vec::new();
        for found in listing {
            let path = found.map_err(|error| io_error(&self.dir, &error))?.path();
            if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("yaml") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            if is_flow_id(stem) {
                files.push((stem.to_string(), path));
            }
        }
        Ok(files)
    }
}

/// Builds an entry, validating the text and holding the id the file claims.
fn entry(id: &str, source: Source, path: Option<PathBuf>, yaml: String) -> Entry {
    let parsed = parse(&yaml).and_then(|flow| {
        if flow.id == id {
            Ok(flow)
        } else {
            Err(FlowError::Invalid {
                path: "id".to_string(),
                message: format!(
                    "the flow declares id `{}` but the file is `{id}.yaml`",
                    flow.id
                ),
            })
        }
    });
    Entry {
        id: id.to_string(),
        source,
        path,
        yaml,
        parsed,
    }
}

fn read(path: &Path) -> Result<String, FlowError> {
    fs::read_to_string(path).map_err(|error| io_error(path, &error))
}

fn io_error(path: &Path, error: &io::Error) -> FlowError {
    FlowError::Io(format!("{}: {error}", path.display()))
}

/// Whether a name can be a flow id, and so a file name in the library.
fn is_flow_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}
