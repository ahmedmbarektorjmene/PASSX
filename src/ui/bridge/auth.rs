use windows::core::*;

pub fn authenticate_user() -> bool {
    unsafe {
        
        use windows::Security::Credentials::UI::*;
        use windows::core::HSTRING;
        use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
        use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
        use windows::Foundation::IAsyncOperation;

        println!("[DEBUG] Calling UserConsentVerifier with window interop...");
        
        let message = HSTRING::from("PASSX is trying to show the password. Type your Windows password to allow this.");
        
        // Get the interop factory for UserConsentVerifier
        let interop: Result<IUserConsentVerifierInterop> = windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>();
        
        if let Ok(interop_factory) = interop {
            let hwnd = GetForegroundWindow();
            // Call the interop version which takes an HWND to center the dialog
            let operation: Result<IAsyncOperation<UserConsentVerificationResult>> = interop_factory.RequestVerificationForWindowAsync(hwnd, &message);
            
            if let Ok(async_op) = operation {
                match async_op.get() {
                    Ok(result) => {
                        println!("[DEBUG] UserConsentVerificationResult: {:?}", result);
                        return result == UserConsentVerificationResult::Verified;
                    }
                    Err(e) => {
                        println!("[DEBUG] UserConsentVerifier failed: {:?}", e);
                        return false;
                    }
                }
            }
        }
        
        // Fallback to standard version if interop fails
        let operation = UserConsentVerifier::RequestVerificationAsync(&message);
        if let Ok(async_op) = operation {
            return async_op.get().map(|r| r == UserConsentVerificationResult::Verified).unwrap_or(false);
        }
        
        false
    }
}
