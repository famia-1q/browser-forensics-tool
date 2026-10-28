# Running the tool on Windows

There are two ways. Use the first one unless you want to read or change the code.

## Option 1: BrowserForensics.exe (no Python needed)

**Getting the file (Ayesha, once per new version)**

1. Push to GitHub. The "Windows app" workflow starts by itself.
2. On GitHub open the repository, then **Actions**, then **Windows app**, then the newest run with a green tick.
3. At the bottom, under **Artifacts**, click **BrowserForensics-windows**. A zip downloads.
4. Send the zip to your teammate (WhatsApp, Google Drive or a USB stick). The repository is private, so they cannot download it from GitHub themselves unless you add them as a collaborator.

**Opening it (teammate)**

1. Unzip it and double-click `BrowserForensics.exe`.
2. The first time, Windows may show "Windows protected your PC". Click **More info**, then **Run anyway**. This appears because the program is not signed with a paid certificate, not because anything is wrong with it. If your antivirus quarantines it, restore it and allow it.
3. The tool opens in its own window on the home screen. It takes a few seconds the first time.

Cases are saved in `Documents\Browser Forensics\evidence`.

## Option 2: from the project folder (to see the code in VS Code)

1. Install Python 3.12 from https://www.python.org/downloads/ and keep the default options. The `py` launcher is included.
2. Get the project folder: either `git clone` it (you need to be added as a collaborator), or ask Ayesha for a zip of the folder.
3. Double-click `start.bat`. Or open the folder in VS Code and press **Ctrl+Shift+B** (or **F5** with the Python extension installed).
4. The tool opens in your default browser. For its own window instead, run `py -m pip install pywebview` once.

## Using it

**Capture the browser**

1. Do not close Chrome or Firefox, or any tabs.
2. Click **Capture the browser**, check the list of profiles, click **Capture now**.
3. If a file is listed as skipped, Chrome is locking it. Windows does this while Chrome is open. If you also need a memory snapshot, take it first (below). Then close Chrome and click **Capture now** again.
4. When it says "Captured and hashed", you can close the browser. Click **Open results**.

**Memory snapshot (VMware Workstation)**

1. Leave the browser and its private window open in the virtual machine.
2. In VMware Workstation: **VM**, then **Snapshot**, then **Take Snapshot**. Wait until it finishes, which can take a few minutes.
3. In the tool click **Memory snapshot**. The snapshot appears in the list (the tool looks in `Documents\Virtual Machines`). Choose which case to add it to and click **Scan**.
4. If your virtual machines are stored somewhere else, drag the `.vmem` file from that folder onto the drop area. If the tool cannot find it, move the virtual machine folder into Documents, Desktop or Downloads, or run `py -m bft memscan "path\to\file.vmem" --evidence evidence\case1` from the project folder.

**Demo case**

Click **Open demo case**. It builds a fictional case in about ten seconds and opens it. Use it for practice and for the presentation, so no real browsing is shown.

## If something goes wrong

- **The window stays blank or does not open:** the tool falls back to your default browser if the Windows web view (WebView2) is missing. WebView2 is part of Windows 10 and 11; it can be reinstalled from Microsoft's WebView2 page.
- **"Another task is still running":** wait for the current capture or scan to finish. A 4 GB snapshot takes a few minutes.
- **Nothing found under Capture the browser:** Chrome and Firefox were not found in their usual places for this Windows user.
