use windows::Win32::System::JobObjects::{
    CreateJobObjectW, SetInformationJobObject, AssignProcessToJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Enforce sandbox restrictions on the current process using Windows Job Objects.
/// Returns true if successful.
pub fn enter_sandbox() -> bool {
    unsafe {
        // Create a job object
        let Ok(job) = CreateJobObjectW(None, None) else {
            return false;
        };
        
        if job.is_invalid() {
            return false;
        }

        // Configure basic limits
        let mut limits = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
        limits.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | 
                            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        
        let mut extended_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        extended_info.BasicLimitInformation = limits;
        
        // Apply limits
        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &extended_info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ).is_err() {
            return false;
        }

        // Assign current process to job
        if AssignProcessToJobObject(job, GetCurrentProcess()).is_err() {
            return false;
        }
        
        // Leak the job handle so it persists for lifetime of process
        // Job handle is Copy but we don't close it, effectively leaking it.
        // std::mem::forget(job); 
        
        true
    }
}
