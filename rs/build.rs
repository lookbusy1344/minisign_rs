use std::process::Command;

fn main() {
    // Get commit hash from git
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output();

    let commit_hash = match output {
        Ok(output) if output.status.success() => {
            let hash = String::from_utf8_lossy(&output.stdout);
            // Take first 7 characters (standard short hash)
            hash.trim().chars().take(7).collect()
        }
        _ => {
            // Fallback for non-git builds (tarballs, etc.)
            "unknown".to_string()
        }
    };

    // Set environment variable for use in source code
    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", commit_hash);

    // Rebuild if git HEAD changes (new commits)
    println!("cargo:rerun-if-changed=../.git/HEAD");
}
