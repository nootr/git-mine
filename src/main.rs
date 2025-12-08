use rayon::prelude::*;
use sha1::{Digest, Sha1};
use std::env;
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tempfile::NamedTempFile;

/// Checks if a SHA-1 hash starts with the given prefix.
fn hash_starts_with_prefix(hash: &[u8], prefix: &str) -> bool {
    // Convert hash bytes to hex string
    let hex_string = hash.iter()
        .take(prefix.len().div_ceil(2) + 1)  // Only convert what we need
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    hex_string.to_lowercase().starts_with(&prefix.to_lowercase())
}

/// Calculates the SHA-1 hash of a git commit with the given parameters.
/// Optimized to minimize allocations in the hot path.
fn calculate_commit_hash(
    tree: &str,
    parent: &str,
    author: &str,
    committer: &str,
    message: &str,
    nonce: u64,
) -> [u8; 20] {
    use std::fmt::Write as FmtWrite;

    // Build commit object with single allocation
    let mut commit_content = String::with_capacity(512);

    writeln!(commit_content, "tree {}", tree).unwrap();
    if !parent.is_empty() {
        writeln!(commit_content, "parent {}", parent).unwrap();
    }
    write!(commit_content, "author {}\ncommitter {}\n\n{}\n\n\nnonce: {}\n",
           author, committer, message, nonce).unwrap();

    // Calculate SHA-1 with git header
    let mut hasher = Sha1::new();
    let header = format!("commit {}\0", commit_content.len());
    hasher.update(header.as_bytes());
    hasher.update(commit_content.as_bytes());

    hasher.finalize().into()
}

fn mine_commit(
    tree: String,
    parent: String,
    author: String,
    committer: String,
    message: String,
    prefix: String,
) -> Option<u64> {
    let found = Arc::new(AtomicBool::new(false));
    let result_nonce = Arc::new(AtomicU64::new(0));
    let attempts = Arc::new(AtomicU64::new(0));

    let start_time = Instant::now();
    const BATCH_SIZE: u64 = 1_000_000;

    println!("⛏️  Mining with {} CPU threads...", rayon::current_num_threads());

    for batch in 0.. {
        if found.load(Ordering::Acquire) {
            break;
        }

        let start_nonce = batch * BATCH_SIZE;
        let end_nonce = start_nonce + BATCH_SIZE;

        // Process batch in parallel
        let batch_result: Option<u64> = (start_nonce..end_nonce)
            .into_par_iter()
            .find_any(|&nonce| {
                if found.load(Ordering::Acquire) {
                    return false;
                }

                let hash = calculate_commit_hash(&tree, &parent, &author, &committer, &message, nonce);

                if hash_starts_with_prefix(&hash, &prefix) {
                    found.store(true, Ordering::Release);
                    result_nonce.store(nonce, Ordering::Release);
                    return true;
                }
                false
            });

        attempts.fetch_add(BATCH_SIZE, Ordering::Relaxed);

        // Progress update every 10 batches
        if batch % 10 == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let total_attempts = attempts.load(Ordering::Relaxed);
            if elapsed > 0.0 {
                let rate = total_attempts as f64 / elapsed;
                print!(
                    "\rAttempt {}... ({:.1} K/s)  ",
                    total_attempts,
                    rate / 1000.0
                );
                std::io::stdout().flush().unwrap();
            }
        }

        if batch_result.is_some() {
            break;
        }
    }

    if found.load(Ordering::Acquire) {
        let final_nonce = result_nonce.load(Ordering::Acquire);
        let elapsed = start_time.elapsed().as_secs_f64();
        let total_attempts = attempts.load(Ordering::Relaxed);

        println!("\n✨ SUCCESS! Found nonce: {} after {} attempts", final_nonce, total_attempts);
        if elapsed > 0.0 {
            println!("⏱️  Time taken: {:.2}s ({:.1} K/s)", elapsed, total_attempts as f64 / elapsed / 1000.0);
        }

        Some(final_nonce)
    } else {
        None
    }
}

fn get_git_output(args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute git: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Git command failed: git {}\nError: {}",
            args.join(" "),
            stderr.trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn amend_commit_with_nonce(
    nonce: u64,
    original_message: &str,
    author_date: &str,
    committer_date: &str
) -> Result<(), String> {
    let full_message = format!("{}\n\n\nnonce: {}\n", original_message, nonce);

    // Use secure temp file handling
    let mut temp_file = NamedTempFile::new()
        .map_err(|e| format!("Failed to create temp file: {}", e))?;

    temp_file.write_all(full_message.as_bytes())
        .map_err(|e| format!("Failed to write temp file: {}", e))?;

    let temp_path = temp_file.path();

    // Amend commit
    let output = Command::new("git")
        .args(["commit", "--amend", "--allow-empty", "-F"])
        .arg(temp_path)
        .args(["--quiet", "--no-verify", "--cleanup=verbatim"])
        .env("GIT_AUTHOR_DATE", author_date)
        .env("GIT_COMMITTER_DATE", committer_date)
        .output()
        .map_err(|e| format!("Failed to execute git commit: {}", e))?;

    // temp_file is automatically cleaned up when dropped

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to amend commit: {}", stderr.trim()));
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse prefix argument (default: "BADC0DE")
    let prefix = if args.len() > 1 {
        let input = &args[1];

        // Validate hex characters
        if !input.chars().all(|c| c.is_ascii_hexdigit()) {
            eprintln!("❌ Error: Prefix must contain only hex characters (0-9, A-F)");
            eprintln!("💡 Usage: git mine [PREFIX]");
            eprintln!("💡 Example: git mine BADC0DE");
            std::process::exit(1);
        }

        if input.len() > 40 {
            eprintln!("❌ Error: Prefix too long (max 40 characters)");
            std::process::exit(1);
        }

        input.to_string()
    } else {
        "BADC0DE".to_string()
    };

    println!("⛏️  Mining for commit hash starting with '{}'...", prefix.to_uppercase());

    // Check if in git repo with better error handling
    let git_check = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output();

    match git_check {
        Ok(output) if output.status.success() => {},
        Ok(_) => {
            eprintln!("❌ Error: Not in a git repository");
            eprintln!("💡 Run 'git init' first");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Error: Failed to run git: {}", e);
            eprintln!("💡 Make sure git is installed and in your PATH");
            std::process::exit(1);
        }
    }

    // Check if there's a commit
    let head_check = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output();

    match head_check {
        Ok(output) if output.status.success() => {},
        Ok(_) => {
            eprintln!("❌ Error: No commit found");
            eprintln!("💡 Create a commit first with: git commit");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Error: Failed to check for commits: {}", e);
            std::process::exit(1);
        }
    }

    // Get commit object once
    let commit_obj = get_git_output(&["cat-file", "-p", "HEAD"])
        .unwrap_or_else(|e| {
            eprintln!("❌ Error reading commit: {}", e);
            std::process::exit(1);
        });

    // Parse tree (required)
    let tree = commit_obj.lines()
        .find(|l| l.starts_with("tree "))
        .and_then(|l| l.split_whitespace().nth(1))
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            eprintln!("❌ Error: No tree hash found in commit");
            std::process::exit(1);
        });

    // Parse parent (optional)
    let parent = commit_obj.lines()
        .find(|l| l.starts_with("parent "))
        .and_then(|l| l.split_whitespace().nth(1))
        .map(|s| s.to_string())
        .unwrap_or_default();

    // Get original message - use git log to preserve formatting
    let original_message = get_git_output(&["log", "-1", "--format=%B"])
        .unwrap_or_else(|e| {
            eprintln!("❌ Error reading commit message: {}", e);
            std::process::exit(1);
        })
        .trim_end_matches('\n')
        .to_string();

    // Get author info
    let author_name = get_git_output(&["log", "-1", "--format=%an"]).unwrap_or_default();
    let author_email = get_git_output(&["log", "-1", "--format=%ae"]).unwrap_or_default();
    let author_timestamp = get_git_output(&["log", "-1", "--format=%at"]).unwrap_or_default();
    let author_tz = get_git_output(&["log", "-1", "--format=%ad", "--date=format:%z"]).unwrap_or_default();

    let author = format!("{} <{}> {} {}", author_name, author_email, author_timestamp, author_tz);
    let author_date = format!("{} {}", author_timestamp, author_tz);

    // Get committer info
    let committer_name = get_git_output(&["config", "user.name"]).unwrap_or_else(|_| {
        eprintln!("❌ Error: Git user.name not configured");
        eprintln!("💡 Run: git config --global user.name \"Your Name\"");
        std::process::exit(1);
    });

    let committer_email = get_git_output(&["config", "user.email"]).unwrap_or_else(|_| {
        eprintln!("❌ Error: Git user.email not configured");
        eprintln!("💡 Run: git config --global user.email \"your@email.com\"");
        std::process::exit(1);
    });

    let committer_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let committer = format!("{} <{}> {} +0000", committer_name, committer_email, committer_timestamp);
    let committer_date = format!("{} +0000", committer_timestamp);

    // Mine!
    match mine_commit(tree, parent, author, committer, original_message.clone(), prefix.clone()) {
        Some(nonce) => {
            println!("\n✨ Found winning nonce: {}\n", nonce);

            // Amend the commit
            if let Err(e) = amend_commit_with_nonce(nonce, &original_message, &author_date, &committer_date) {
                eprintln!("❌ Error: {}", e);
                std::process::exit(1);
            }

            // Show result
            let new_hash = get_git_output(&["rev-parse", "HEAD"]).unwrap_or_default();
            println!("🎉 Your mined commit is ready!");
            println!("📝 Commit hash: {}\n", new_hash);

            let _ = Command::new("git").args(["log", "-1", "--oneline"]).status();
        }
        None => {
            eprintln!("❌ Mining failed");
            std::process::exit(1);
        }
    }
}
