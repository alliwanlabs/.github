# The image scan runner: Spark first, GitHub-hosted when Spark cannot

The shared security baseline (`.github/workflows/security-baseline.yml`) builds each repository's image, scans
it with Trivy (fixable HIGH and CRITICAL fail) and uploads a CycloneDX SBOM. Since 19 November 2026 the scan runs
on the self-hosted Spark scan runners when one is available and on a GitHub-hosted runner when it is not. The
scan itself never changes and is never skipped: only the machine it runs on does.

Before this change the image job waited for a Spark runner with no way out. On 18 and 19 November jobs either sat
in the queue with no runner or stalled in checkout until the 25-minute limit cancelled them, and the cancelled
check run blocked the travelai-azure promotion of Rihla 9.27.

## How the placement is decided

1. **Plan job (GitHub-hosted, seconds).** When the image is due, the step "Choose the scan runner" decides where
   it runs, before any job waits for a runner. A job queued for a self-hosted label that no online runner carries
   waits for hours and cannot time out, so this check has to come first.
   - With the runner-status App (variable `LABS_SCAN_STATUS_APP_ID`, secret passed as `scan-status-app-key`) it
     mints a token that can only read self-hosted runners and runner groups. It places the scan on Spark when a
     runner carrying `self-hosted`, `spark` and `scan` is online in a runner group the repository may use. It
     looks three times, 20 seconds apart, because the ephemeral runners re-register between jobs.
   - Missing credentials, a failed API call or no such runner: GitHub-hosted. Every doubt falls toward the
     GitHub-hosted scan, never toward skipping it.
2. **"Image and SBOM (Trivy) on Spark"** runs only when the plan chose Spark. Each step that can stall on the
   runner has its own timeout: checkout 5 minutes, Trivy install 5, build `spark-build-minutes` (default 15),
   SBOM 12, SBOM upload 5, scan 12. A stall or an infrastructure error ends the job **green**, with the warning
   "Scan runner stalled or failed at the <step> step on <runner>. This is the runner, not the code". Only a real
   finding (Trivy exit code 13) fails this job.
3. **"Image and SBOM (Trivy)"** (the name the check has always had) runs on GitHub-hosted whenever the image is
   due. When Spark scanned and passed, it records that and ends in a few seconds. When Spark found
   vulnerabilities, it fails. Otherwise (Spark not chosen, stalled or failed) it builds, writes the SBOM and scans
   the image itself.

On a run where Spark stalled, the commit therefore carries a green Spark check with a warning and a green or red
"Image and SBOM (Trivy)" that holds the real verdict. There is no cancelled or failed check run for the stall, so
travelai-azure's merge guard and promote gate see only the scan result.

What the fallback does not cover:

- A runner the API reports online that never picks the job up. The job then waits in the queue. The monitor below
  opens an issue after 15 minutes; cancel the run and re-run it with `LABS_SCAN_RUNNER=hosted` (below).
- A runner that dies mid-job ("lost communication with the server"), or a stall in "Set up job" before the first
  step. Both end in a red or cancelled Spark check. Re-run the failed jobs; the plan job places the re-run again.

## Overrides: `LABS_SCAN_RUNNER` and `heavy-runner`

The caller input `heavy-runner` wins over the variable `LABS_SCAN_RUNNER` (organisation or repository level).

| Value | Effect |
|---|---|
| empty or `auto` | The automatic placement above. The normal setting. |
| `spark` | Spark without the runner check. Stalls still hand over to GitHub-hosted; a job queued with no runner online is not covered. Only for use while the runner-status App is missing. |
| `hosted` | GitHub-hosted (`ubuntu-latest`) for every image scan, no Spark job at all. |
| a label, plain or JSON (`ubuntu-latest`, `"ubuntu-latest"`, `["self-hosted","x"]`) | That runner, never Spark. |

**Who may set it.** `LABS_SCAN_RUNNER` is an Actions variable: an organisation owner sets it for every
repository, a repository admin for one repository. Agents never change it. **When.** Only when the automatic
placement is not enough: `hosted` while the Spark runners are known to be broken in a way the API does not show
(online but not taking jobs), and back to empty once the monitor issue closes. Write the change and the reason in
the monitor issue.

```bash
gh variable set LABS_SCAN_RUNNER --org alliwanlabs --visibility private --body hosted   # every private repository
gh variable set LABS_SCAN_RUNNER -R alliwanlabs/<repo> --body hosted                     # one repository
gh variable delete LABS_SCAN_RUNNER --org alliwanlabs                                    # back to auto
```

## The runner-status App (one-time set-up, organisation owner)

A dedicated GitHub App, not `alliwanlabs-agents`: its private key sits in an Actions secret that every private
repository can read, so the App must hold nothing but read access to runners and Actions.

1. Create the App under the organisation: name `alliwanlabs-scan-status`, no webhook, permissions
   **Organization: Self-hosted runners: Read** and **Repository: Actions: Read** (the monitor reads queued jobs),
   nothing else. Install it on the organisation, all repositories.
2. Organisation variable `LABS_SCAN_STATUS_APP_ID` = the App ID, visibility private repositories.
3. Organisation secret `LABS_SCAN_STATUS_APP_KEY` = the App's private key (PEM), visibility private repositories.
4. Callers pass the secret (the caller template already does):

   ```yaml
   jobs:
     baseline:
       uses: alliwanlabs/.github/.github/workflows/security-baseline.yml@<pin>
       secrets:
         scan-status-app-key: ${{ secrets.LABS_SCAN_STATUS_APP_KEY }}
   ```

Until all four are in place, `auto` scans every image on GitHub-hosted.

## The monitor

`alliwanlabs/azure-baseline`, `.github/workflows/scan-runner-monitor.yml`, every 30 minutes on GitHub-hosted. It
keeps one issue labelled `scan-runner-alert` in azure-baseline open while a Spark runner is offline, fewer than
`LABS_SCAN_RUNNERS_EXPECTED` (default 2) are online, or a Spark image job has been queued for more than
15 minutes. It comments when the findings change and closes the issue when everything is healthy. It is skipped
until `LABS_SCAN_STATUS_APP_ID` exists.

## Cost

GitHub-hosted Linux minutes cost $0.006 each on the organisation's Team plan. From 20 October to 19 November 2026
the organisation ran about 1,280 image jobs.

- The verdict job on every image run: about 1 billed minute each, about 1,300 minutes ($8) a month.
- A full GitHub-hosted scan: 1 to 3 billed minutes for a small image, about 5 for an application image. If every
  image fell back (no App, or Spark down all month), about 6,500 minutes ($40) a month.
- The monitor: about 1,500 minutes ($9) a month.

The organisation used about 53,000 GitHub-hosted minutes in the first 19 days of November 2026.
