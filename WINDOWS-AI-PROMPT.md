# Prompt for setting up the tool on Windows with Claude or ChatGPT

Copy everything inside the box below into Claude (Claude Code or claude.ai), ChatGPT, Codex or a similar assistant. Fill in the two blanks first.

```text
You are helping me set up, test and build a Python project called Browser Forensics Tool (bft) on my Windows laptop. It is our Digital Forensics midterm project. My teammate built it on a Mac; my job is to prove it runs on Windows and to understand it well enough to present it.

My Windows version: ________ (Settings > System > About)
Where the project folder is: ________ (for example C:\Users\me\Documents\browser-forensics-tool)

How to work with me:
- If you can run commands yourself, run them in PowerShell from the project folder and show me the output. If you cannot, give me ONE command at a time and wait for me to paste the output before the next one.
- Do not change, delete or rewrite any file in the project. If something fails, show me the exact error, explain the cause in plain words, and propose a fix. I will check with my teammate before any code changes.
- Do not commit or push anything to GitHub.
- Do not capture my real browsers until I say "capture now". Use the built-in demo case for all testing.
- Do not install anything system-wide except Python. Extra packages go into a virtual environment inside the project folder.
- Never paste my real browsing history, URLs or cookies back into the chat. Counts only.

Step 1. Python
Run: py -3 --version
It must say 3.9 or newer. If "py" is not found, try: python --version
If neither works, tell me to install Python 3.12 from https://www.python.org/downloads/ with the default options, then close and reopen PowerShell.
From here on, use whichever command worked ("py -3" or "python").

Step 2. Unit tests (standard library only, nothing to install)
Run: py -3 -m unittest -v
Expected: the last lines say "Ran 36 tests" and "OK". If anything fails or errors, show me the full failure text.

Step 3. The tool in the browser
Run: py -3 -m bft app --no-window
My default browser should open on a home screen with three buttons: Capture the browser, Memory snapshot, Open demo case.
Tell me to click "Open demo case". Expected after about ten seconds:
- 224 records
- Integrity: PASSED (80 ok, 0 mismatch, 0 missing)
- Tag filter set to "private" shows 5 history and 2 search records
- Tag filter set to "deleted" shows 25 records
Then stop the tool with Ctrl+C in PowerShell.

Step 4. The tool in its own window
Run, one at a time:
  py -3 -m venv .venv
  .venv\Scripts\python -m pip install pywebview pyinstaller
  .venv\Scripts\python -m bft app
Do not run Activate.ps1 and do not change the PowerShell execution policy; calling .venv\Scripts\python directly avoids both.
Expected: a window titled "Browser Forensics" with the same home screen. If no window opens, the tool falls back to the default browser; tell me, because it means the Microsoft Edge WebView2 runtime is missing.

Step 5. Build the .exe
Run: .venv\Scripts\python packaging\build.py
Expected: dist\BrowserForensics.exe. Tell me to double-click it.
If Windows shows "Windows protected your PC": More info, then Run anyway (the file is not code-signed).
If Microsoft Defender quarantines it, tell me how to restore it and allow it.
The .exe keeps its cases in Documents\Browser Forensics\evidence.
The dist and build folders are ignored by git; do not commit them.

Step 6. Real capture (ONLY after I say "capture now")
- Keep Chrome and Firefox open, with their tabs. Closing Firefox rewrites its history file and can destroy deleted entries the tool would recover.
- In the tool: Capture the browser, check the profiles, Capture now.
- On Windows a running Chrome locks its History file. If the result lists skipped files, that is expected: if I also need a memory snapshot, take it first (step 7), then close Chrome and click Capture now again.
- Report only the record counts and the integrity line.

Step 7. Memory snapshot (only if I use VMware Workstation)
- Leave the browser and its private window open in the virtual machine.
- VMware Workstation: VM > Snapshot > Take Snapshot. Wait until it finishes.
- In the tool: Memory snapshot. The snapshot (.vmem) should be listed if the VM lives in Documents\Virtual Machines. Choose the case to add it to, then Scan.
- If it is not listed, I can drag the .vmem file onto the drop area. If the tool cannot find it, the VM folder must be inside Documents, Desktop or Downloads.

Step 8. Write up the results
Create a file called windows-run.txt in the project folder (do not commit it) containing:
- Windows version and Python version
- The "Ran ... tests" line and OK or FAILED
- Demo case: record count, integrity line, private and deleted counts
- Whether the app window opened (step 4)
- Whether the .exe built and opened (step 5)
- Real capture and snapshot: counts and integrity only, if done
- Every error message seen, word for word
I will send this file to my teammate for our report's cross-platform section.

Step 9. Help me understand it for the presentation
After everything works, explain in plain language, one at a time, waiting for me to say "next":
1. What bft/acquire.py does and why every file is hashed
2. How bft/firefox.py reads places.sqlite and converts Firefox timestamps
3. How bft/carve.py recovers deleted history from SQLite free space
4. How bft/memscan.py tags pages as private or deleted
5. How bft/web/server.py stops other websites from triggering a capture
Read the actual code before explaining. Do not guess.
```

## Getting the project onto the Windows laptop

- **Easiest:** Ayesha zips the project folder (without `evidence/` and `demo-profiles/`) and sends it.
- **With git:** Ayesha adds the teammate's GitHub account under Settings, Collaborators, then the teammate runs `git clone https://github.com/ashubena/browser-forensics-tool.git`.
- **Only the program, no code:** download `BrowserForensics.exe` from the latest "Windows app" run on GitHub (see `WINDOWS.md`). Steps 1 to 5 are then not needed.
