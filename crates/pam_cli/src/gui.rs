use std::{env, path::PathBuf, process::Command};

const GUI_EXECUTABLE: &str = if cfg!(windows) {
    "pam-gui.exe"
} else {
    "pam-gui"
};

pub(crate) fn run() -> i32 {
    match launch() {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn launch() -> Result<std::process::ExitStatus, String> {
    let executable = gui_executable()?;
    Command::new(&executable)
        .current_dir(env::current_dir().map_err(|error| {
            format!("PAM could not resolve the current project directory: {error}")
        })?)
        .status()
        .map_err(|error| {
            format!(
                "PAM could not launch the bundled desktop application at {}: {error}",
                executable.display()
            )
        })
}

fn gui_executable() -> Result<PathBuf, String> {
    #[cfg(debug_assertions)]
    if let Some(path) = env::var_os("PAM_GUI_EXECUTABLE") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err("PAM_GUI_EXECUTABLE must be an absolute development path".to_owned());
        }
        return validate_executable(path);
    }

    let current = env::current_exe()
        .map_err(|error| format!("PAM could not resolve its installed executable: {error}"))?;
    let parent = current
        .parent()
        .ok_or_else(|| "PAM's installed executable has no parent directory".to_owned())?;
    validate_executable(parent.join(GUI_EXECUTABLE))
}

pub(super) fn validate_executable(path: PathBuf) -> Result<PathBuf, String> {
    let metadata = path.metadata().map_err(|error| {
        format!(
            "PAM desktop application is unavailable at {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "PAM desktop application path is not a file: {}",
            path.display()
        ));
    }
    Ok(path)
}
