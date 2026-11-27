# External review: what a second model found

Before publishing, the working version was reviewed by OpenAI's Codex (three passes: security,
correctness, documentation). The review ran without giving the reviewer the machine:

- **A scrubbed packet, not the tree.** Only the code and docs were copied out, with hostnames, IPs,
  usernames and paths replaced. gitleaks scanned the packet, after first proving it catches a
  planted canary.
- **A container with nothing else mounted.** The packet, the CLI binary and a throwaway login copy
  were mounted, and the documents were passed inline. The session log showed zero tool calls; the
  login copy was shredded afterwards.
- **Every finding was checked locally** before it counted. Three were reproduced outright.

## What it found, and what changed

| Finding | Reproduced | Change |
|---|---|---|
| A zip containing `[Content_Types].xml` skipped the archive member checks, so a zip with `setup.exe` inside was released as a normal document | yes | Every zip now goes through one member loop. Office detection also requires a real main part. |
| A UTF-16 text file with an SSN passed as normal; the decoder saw interleaved NULs | yes | BOM-aware decoding; NULs without a BOM → `unverified`. |
| The history service could read the encrypted sensitive directory | yes | `InaccessiblePaths=` for every non-ready area. Verified on the original deployment through the running unit's mount namespace. The shipped unit hides every non-ready area under the root; your sensitive directory lives elsewhere, so you add it yourself (see the configuration table). |
| Release hashed the file after the scan, not the bytes the scanner saw | by reading | The scanner returns the hash of what it classified; release compares against it before and after the move. |
| PDF pages after 200 were never examined | by reading | Whole-document extraction with a timeout and a text cap; failure → `unverified`. |
| A FIFO in a drop would block the intake when it was hashed | by reading | Non-regular files are removed without being opened. |
| An incomplete upload moved to `rejected/` kept its old timestamp and was purged in the same run | by reading | Retention restarts on rejection. |
| The acceptance test didn't prove a mid-scan drop was handled in the same run | yes | The unit test now drops a second batch from inside the first scan and asserts two scans in one run. |
| Docs overstated the scanner's output and the recovery procedure | yes | Rewritten to match the code. |

## What was kept as is, and why

- **The scanner reads private-key bytes.** It has to, in order to detect them. The rule "keys are
  never read" applies to the agent, not to the sandboxed scanner.
- **Filenames are visible** in the ledger and on the history page. Treating names as secret would
  make the log useless; the docs say not to put secrets in file names.
- **Downloads are buffered** rather than streamed. That is acceptable at a 200 MB cap.

The reviewer also listed strengths to keep: the sandbox's enum-only output, the download gate
(eligibility + hash recheck + attachment/nosniff/CSP), value-asserting tests, and documentation that
separates enforced boundaries from checks.
