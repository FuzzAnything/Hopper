use std::fmt::Write as _;
use std::{
    fs,
    io::prelude::*,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{config, execute::StatusType, read_program, FuzzProgram, Serialize};

/// Directory of depot, stored all input files.
pub struct DepotDir {
    path: PathBuf,
    size: AtomicUsize,
}

impl DepotDir {
    /// Create new directory of depot
    pub fn new(path: PathBuf) -> eyre::Result<Self> {
        if !path.exists() {
            fs::create_dir(&path)?;
        }
        Ok(Self {
            path,
            size: AtomicUsize::new(0),
        })
    }

    /// Return size of files in this direcotry
    pub fn size(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    /// Get file name of n-th input, where n is ID of the input.
    fn file_name(&self, id: usize) -> PathBuf {
        let file_name = format!("id_{id:06}");
        self.path.join(file_name)
    }

    /// count ID
    pub fn inc_id(&self) -> usize {
        self.size.fetch_add(1, Ordering::Relaxed)
    }

    /// Save program into depot directory
    pub fn save_program(&self, program: &FuzzProgram, status: StatusType) -> eyre::Result<()> {
        let mut buf = program.serialize_all()?;
        if let StatusType::Crash { signal } = status {
            let _ = writeln!(buf, "<SIGNAL> {}", &signal.serialize()?);
        }
        self.save_file(program.id, buf.as_bytes())?;
        Ok(())
    }

    pub fn add_appendix(&self, id: usize, appendix: &str) -> eyre::Result<()> {
        let file_name = self.file_name(id);
        let mut f = fs::OpenOptions::new().append(true).open(file_name)?;
        f.write_all(appendix.as_bytes())?;
        Ok(())
    }

    /// Save program with custom file_name and appendix
    pub fn save_program_custom(
        &self,
        file_name: &str,
        program: &FuzzProgram,
        status: StatusType,
        appendix: Option<String>,
    ) -> eyre::Result<()> {
        let mut buf = program.serialize_all()?;
        if let StatusType::Crash { signal } = status {
            let _ = writeln!(buf, "<SIGNAL> {}", &signal.serialize()?);
        }
        if let Some(ap) = appendix {
            buf.push_str(&ap);
        }
        let path = self.path.join(file_name);
        let mut f = fs::File::create(path)?;
        f.write_all(buf.as_bytes())?;
        f.flush()?;
        Ok(())
    }

    /// Save file into depot directory
    fn save_file(&self, id: usize, buf: &[u8]) -> eyre::Result<()> {
        let file_name = self.file_name(id);
        crate::log!(debug, "save program at file: {:?}", &file_name);
        if !file_name.exists() {
            let mut f = fs::File::create(file_name.as_path())?;
            f.write_all(buf)?;
            f.flush()?;
        }
        Ok(())
    }

    /// List all the files in directory
    pub fn read_dir(&self) -> eyre::Result<Vec<PathBuf>> {
        let mut files = vec![];
        let mut entries: Vec<std::fs::DirEntry> =
            self.path.read_dir()?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|p| p.metadata().unwrap().created().unwrap());
        for entry in entries {
            let path = entry.path();
            if path.is_file() {
                files.push(path);
            }
        }
        Ok(files)
    }

    /// Update size of files in depot's directory (in memory), used for rerun the fuzzer.
    pub fn update_size(&self) -> eyre::Result<()> {
        let size = self.path.read_dir()?.count();
        crate::log!(info, "{:?} has {} files", self.path, size);
        self.size.store(size, Ordering::Relaxed);
        Ok(())
    }
}

/// Initilize depot's directories
pub fn init_depot_dirs() -> eyre::Result<(DepotDir, DepotDir, DepotDir)> {
    crate::log!(info, "init depot dir..");
    let out_dir = PathBuf::from(config::OUTPUT_DIR);
    let inputs_dir = out_dir.join(config::INPUTS_DIR);
    let hangs_dir = out_dir.join(config::HANGS_DIR);
    let crashes_dir = out_dir.join(config::CRASHES_DIR);
    config::create_dir_in_output_if_not_exist(config::MISC_DIR)?;
    config::create_dir_in_output_if_not_exist(config::TMP_DIR)?;
    config::create_dir_in_output_if_not_exist(config::REVIEW_DIR)?;
    Ok((
        DepotDir::new(inputs_dir)?,
        DepotDir::new(hangs_dir)?,
        DepotDir::new(crashes_dir)?,
    ))
}

/// Read program from queue
pub fn read_input_in_queue(id: usize) -> eyre::Result<FuzzProgram> {
    let out_dir = PathBuf::from(config::OUTPUT_DIR);
    let file_name = format!("id_{id:06}");
    let f = out_dir.join(config::INPUTS_DIR).join(file_name);
    let buf = std::fs::read_to_string(f)?;
    let program = read_program(&buf, false)?;
    Ok(program)
}
