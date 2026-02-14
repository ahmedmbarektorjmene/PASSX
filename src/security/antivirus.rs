use std::process::Command;
use std::os::windows::process::CommandExt;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct MpInformation {
    #[serde(rename = "AMServiceEnabled")]
    am_service_enabled: String,
    #[serde(rename = "RealTimeProtectionEnabled")]
    real_time_protection_enabled: String,
    #[serde(rename = "AntivirusEnabled")]
    antivirus_enabled: String,
}

#[derive(Debug, Deserialize)]
struct GenericAvProduct {
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(rename = "productState")]
    product_state: String,
}

pub fn check_antivirus_availability() {
    // 1. Check Windows Defender Deeply
    if check_windows_defender_deep() {
        return; // Defender is active and healthy. Safe to proceed.
    }

    // 2. If Defender is not satisfying, check for other antivirus products
    if check_other_antiviruses_running() {
        return; // Another antivirus is running. Safe to proceed.
    }

    // 3. Check for specific case: Defender exists but is disabled (and no other AV is running)
    // Or just general failure.
    // We can try to see what is detected to give a better error message.
    let detected_avs = get_detected_av_names();
    
    if detected_avs.is_empty() {
         show_alert(
            "Security Alert",
            "No antivirus software detected on your system.\n\nPlease enable Windows Defender or install a security solution to protect your passwords."
        );
    } else {
        let names_str = detected_avs.join(", ");
        show_alert(
            "Security Alert",
            &format!(
                "Your antivirus protection is not active.\n\nDetected products: {}\n\nPlease enable your antivirus software to ensure PASSX runs securely.",
                names_str
            )
        );
    }

    // Force exit if protection is not adequate (as per user requirement "closes... so the program knows if... true")
    std::process::exit(1);
}

fn check_windows_defender_deep() -> bool {
    // Powershell: Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled
    // We use ConvertTo-Csv for easy parsing.
    
    let output = Command::new("powershell")
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .args(&[
            "-NoProfile",
            "-Command",
            "Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled | ConvertTo-Csv -NoTypeInformation"
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Parse CSV
            let mut reader = csv::ReaderBuilder::new()
                .has_headers(true)
                .from_reader(stdout.as_bytes());

            for result in reader.deserialize() {
                let record: MpInformation = match result {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                // Check all true
                // PowerShell boolean output in CSV is usually "True" or "False"
                if record.am_service_enabled.eq_ignore_ascii_case("true") &&
                   record.real_time_protection_enabled.eq_ignore_ascii_case("true") &&
                   record.antivirus_enabled.eq_ignore_ascii_case("true") {
                       return true;
                   }
            }
            false
        }
        _ => {
            // If command fails (e.g. Defender service not running), return false.
            false
        }
    }
}

fn check_other_antiviruses_running() -> bool {
    // User logic:
    // Get-CimInstance ... AntivirusProduct | Where { displayName != 'Windows Defender' }
    // Check if (productState & 0x10000) != 0

    let output = Command::new("powershell")
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .args(&[
            "-NoProfile",
            "-Command",
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Where-Object { $_.displayName -notmatch 'Windows Defender' } | Select-Object displayName, productState | ConvertTo-Csv -NoTypeInformation"
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut reader = csv::ReaderBuilder::new()
                .has_headers(true)
                .from_reader(stdout.as_bytes());

            for result in reader.deserialize() {
                let record: GenericAvProduct = match result {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                if let Ok(state) = record.product_state.parse::<u32>() {
                    // User requested check: productState & 0x10000
                    if (state & 0x10000) != 0 {
                        return true;
                    }
                }
            }
            false
        }
        _ => false // Failed to query WMI or no other AVs
    }
}

fn get_detected_av_names() -> Vec<String> {
     let output = Command::new("powershell")
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .args(&[
            "-NoProfile",
            "-Command",
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName | ConvertTo-Csv -NoTypeInformation"
        ])
        .output();

      let mut names = Vec::new();
      if let Ok(out) = output {
          let stdout = String::from_utf8_lossy(&out.stdout);
          let mut reader = csv::ReaderBuilder::new().has_headers(true).from_reader(stdout.as_bytes());
          // Simple struct for just name
          #[derive(Deserialize)]
          struct NameOnly { display_name: String }
          
          for result in reader.deserialize() {
              if let Ok(record) = result {
                  let r: NameOnly = record;
                  names.push(r.display_name);
              }
          }
      }
      names
}

fn show_alert(title: &str, message: &str) {
    rfd::MessageDialog::new()
        .set_title(title)
        .set_description(message)
        .set_level(rfd::MessageLevel::Warning)
        .set_buttons(rfd::MessageButtons::Ok)
        .show();
}
