use self_update::cargo_crate_version;

pub fn check_for_updates() -> Result<Option<self_update::update::Release>, Box<dyn std::error::Error>> {
    let status = self_update::backends::github::Update::configure()
        .repo_owner("ahmedmbarektorjmene")
        .repo_name("PASSX")
        .bin_name("passx")
        .show_download_progress(true)
        .current_version(cargo_crate_version!())
        .build()?
        .detect_latest_release()?;

    match status {
        self_update::update::ReleaseStatus::UpToDate => Ok(None),
        self_update::update::ReleaseStatus::Updated(release) => Ok(Some(release)),
        _ => Ok(None), // Should not happen with detect_latest_release, but good to cover
    }
}

pub fn update_to_latest() -> Result<(), Box<dyn std::error::Error>> {
    let status = self_update::backends::github::Update::configure()
        .repo_owner("ahmedmbarektorjmene")
        .repo_name("PASSX")
        .bin_name("passx")
        .show_download_progress(true)
        .current_version(cargo_crate_version!())
        .build()?
        .update()?;
        
    println!("Update status: `{:?}`!", status);
    Ok(())
}
