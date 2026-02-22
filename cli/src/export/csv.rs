use crate::export::Config;
use indicatif::ProgressBar;
use std::error::Error;
use std::path::PathBuf;
use ufwlog::UfwLog;

pub fn convert(logs: Vec<UfwLog>, config: Config) -> Result<(), Box<dyn Error>> {
    // resolve file path and name
    let mut path = PathBuf::from(config.output_filename);
    if path.file_name().is_none() {
        return Err("Please specify a file name.".into());
    }
    if path.extension().is_none() {
        path.set_extension(ufwlog::ExportFormat::Csv.get_extension());
    };
    // if the file exists, return error
    if path.exists() && !config.overwrite {
        return Err(format!(
            "The file {} is exist. Overwrite it with `--overwrite` flag.",
            path.to_str().unwrap()
        )
        .into());
    }

    let mut wtr = csv::Writer::from_path(path.to_str().unwrap())?;
    wtr.write_record(ufwlog::CSV_HEADER)
        .expect("Write failed when try to insert header row.");

    let pb = ProgressBar::new(logs.len() as u64);
    for i in logs {
        let row = i.to_csv_vec();

        wtr.write_record(row).expect("Write csv file occur error");

        pb.inc(1); // increase progress bar
    }
    pb.finish();

    Ok(())
}
