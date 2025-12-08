# git-mine

Mine git commit hashes with custom prefixes. Multi-threaded proof-of-work for your commits.

## Installation

```bash
cargo install git-mine
```

## Usage

```bash
# Create a commit like usual
git commit -m "Your message"

# Mine for a custom prefix
git mine BADC0DE

# Or use the default (BADC0DE)
git mine
```

## Examples

```bash
$ git mine 00
⛏️  Mining for commit hash starting with '00'...
✨ SUCCESS! Found nonce: 750100
📝 Commit hash: 00f705f...

$ git mine BADC0DE
⛏️  Mining for commit hash starting with 'BADC0DE'...
```

## How it works

Adds a nonce to your commit message and tries different values until the commit hash starts with your prefix. Uses all CPU cores for parallel mining.
