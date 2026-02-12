fn main() {
    slint_build::compile("src/ui/main_window.slint").unwrap();
    println!("cargo:rerun-if-changed=src/ui/main_window.slint");
    println!("cargo:rerun-if-changed=src/ui/components.slint");
    println!("cargo:rerun-if-changed=src/ui/theme.slint");
    println!("cargo:rerun-if-changed=src/ui/screens/launch.slint");
    println!("cargo:rerun-if-changed=src/ui/screens/create_vault.slint");
    println!("cargo:rerun-if-changed=src/ui/screens/unlock.slint");
    println!("cargo:rerun-if-changed=src/ui/screens/main_vault.slint");
    println!("cargo:rerun-if-changed=src/ui/screens/add_totp.slint");
    println!("cargo:rerun-if-changed=src/ui/screens/generator.slint");
    println!("cargo:rerun-if-changed=src/ui/screens/totp_modal.slint");
    println!("cargo:rerun-if-changed=src/ui/screens/totp_card.slint");
    println!("cargo:rerun-if-changed=src/ui/screens/detail_panel.slint");
    println!("cargo:rerun-if-changed=src/ui/screens/account_modal.slint");
    println!("cargo:rerun-if-changed=src/ui/screens/settings.slint");
    println!("cargo:rerun-if-changed=src/ui/screens/settings.slint");

    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        // Sets the icon for the executable (Explorer)
        // Requires a .ico file.
        res.set_icon("assets/logo.ico");
        res.compile().unwrap();
    }
}
