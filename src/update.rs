use self_update::cargo_crate_version;

pub fn check_for_updates() -> Result<Option<self_update::update::Release>, Box<dyn std::error::Error>> {
    let current_ver = cargo_crate_version!();
    let release = self_update::backends::github::Update::configure()
        .repo_owner("ahmedmbarektorjmene")
        .repo_name("PASSX")
        .bin_name("passx")
        .show_download_progress(true)
        .current_version(current_ver)
        .build()?
        .get_latest_release()?;

    if self_update::version::bump_is_greater(current_ver, &release.version)? {
        Ok(Some(release))
    } else {
        Ok(None)
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
