fn main() {
    let git_describe = std::process::Command::new("git")
        .args(["describe", "--tags", "--always"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout).ok()
            } else {
                None
            }
        })
        .map_or_else(|| "unknown".to_owned(), |s| s.trim().to_owned());

    println!("cargo:rustc-env=GIT_DESCRIBE={git_describe}");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs/");
}
