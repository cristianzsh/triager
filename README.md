# Triager: A DFIR automation script

`Triager` is a Python-based DFIR automation tool designed to automatically parse Windows forensic artifacts collected during incident response and post-incident investigations. Instead of manually running dozens of tools and parsing heterogeneous outputs, `Triager` orchestrates evidence extraction, invokes well-known forensic utilities, normalizes results into CSV format, and organizes findings in a consistent investigation-ready layout.

The tool is designed to work against **triage collections** (e.g., obtained via `KAPE` or `Velociraptor`).

# Motivation

DFIR investigations rely on a large number of forensic artifacts, each requiring specialized tools, formats, and interpretation. Manually parsing these artifacts is time-consuming. With this in mind, `Triager` was created to:

* Automate repetitive forensic parsing tasks
* Reduce analyst investigation time
* Enforce consistent artifact handling and output structure
* Enable faster pivoting, searching, and correlation across artifacts
* Support assisted AI post-processing

The tool focuses on **orchestration**, not reinventing parsers. Whenever possible, it leverages established forensic tools and normalizes their outputs.

# Forensic artifacts overview

Below is a high-level summary of the main artifacts handled by `Triager`:

* **Event Logs (EVTX)** - Used to reconstruct system, security, and application activity timelines, including authentication events, process creation, and security alerts.

* **Prefetch** - Provides evidence of program execution, execution counts, and last run timestamps for executable files.

* **Amcache** - Tracks binaries and metadata, useful for identifying previously executed malware or suspicious tools.

* **Shimcache (AppCompatCache)** - Records historical execution traces, often useful even when Prefetch is absent.

* **BAM/DAM** - Execution artifacts linked to user activity.

* **SRUM** - Contains application usage, network activity, and resource consumption data.

* **Scheduled Tasks** - Common persistence mechanism used by both legitimate software and malware.

* **WMI Repository** - Frequently abused for stealthy persistence mechanisms.

* **Windows Defender Logs** - Provides detection history, verdicts, and alert metadata.

* **WER (Windows Error Reporting)** - Can reveal crashed or abnormal application executions.

* **MFT, USN Journal, and $LogFile** - File system artifacts used to reconstruct file creation, deletion, renaming, and modification activity.

* **Registry (HKLM / HKCU / NTUSER / UsrClass)** - Source of extensive user activity, execution traces, persistence indicators, and configuration data.

* **User Artifacts** - Includes JumpLists, Recent Files, MRUs, Typed Paths, Browser History, PowerShell history, RDP cache, thumbnails, and timelines.

# Requirements

* Python **3.10+** recommended
* Required Python packages:

  ```bash
  pip install pyyaml python-registry requests
  ```

### External tools

Triager relies on multiple external forensic tools, expected to be placed under the `tools/` directory. Examples include (but are not limited to):

* PECmd
* MFTECmd
* AppCompatCacheParser
* SBECmd
* JLECmd
* EvtxECmd
* Hayabusa
* Chainsaw
* APT-Hunter
* SrumECmd
* AmcacheParser
* UserAssistReport

# config.yml

You will need to adjust the `config.yml` file according to your needs. It should specify the locations of the forensic artifacts within the target directory or ZIP file. The default is:

```
root: "D:\\cases\\sample_001\\cape_triage"

# Core Windows paths (relative to triage root)
System32: "uploads\\auto\\C%3A\\Windows\\System32"
EventLogs: "uploads\\auto\\C%3A\\Windows\\System32\\winevt\\Logs"
ScheduledTasks: "uploads\\auto\\C%3A\\Windows\\System32\\Tasks"
Prefetch: "uploads\\auto\\C%3A\\Windows\\Prefetch"
AmCache: "uploads\\auto\\C%3A\\Windows\\AppCompat\\Programs\\Amcache.hve"
PCA: "uploads\\auto\\C%3A\\Windows\\AppCompat\\pca"
WER: "uploads\\auto\\C%3A\\ProgramData\\Microsoft\\Windows\\WER"
WindowsDefenderLogs: "uploads\\auto\\C%3A\\ProgramData\\Microsoft\\Windows Defender\\Support"
SRUM: "uploads\\auto\\C%3A\\Windows\\System32\\sru\\SRUDB.dat"
WMI: "uploads\\auto\\C%3A\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA"

# If present in the triage (depends on how it was collected)
RecycleBin: "uploads\\auto\\C%3A\\$Recycle.Bin"
USNJournal: "uploads\\ntfs\\%5C%5C.%5CC%3A\\$Extend\\$UsnJrnl%3A$J"
MFT: "uploads\\ntfs\\%5C%5C.%5CC%3A\\$MFT"
LogFile: "uploads\\ntfs\\%5C%5C.%5CC%3A\\$LogFile"

# Users root in triage
Users: "uploads\\auto\\C%3A\\Users"

# Registry hives
RegistryHives:
  SYSTEM: "uploads\\auto\\C%3A\\Windows\\System32\\config\\SYSTEM"
  SOFTWARE: "uploads\\auto\\C%3A\\Windows\\System32\\config\\SOFTWARE"
  SAM: "uploads\\auto\\C%3A\\Windows\\System32\\config\\SAM"
  SECURITY: "uploads\\auto\\C%3A\\Windows\\System32\\config\\SECURITY"
  DEFAULT: "uploads\\auto\\C%3A\\Windows\\System32\\config\\DEFAULT"

# Per-user hives patterns
UserHives:
  NTUSERGlob: "Users\\*\\NTUSER.DAT"
  USRCLASSGlob: "Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"
```

# Usage

Basic processing:

```bash
python3 triager.py --root triage_collection.zip -o output_directory
```

Using a ZIP triage archive and custom config file:

```bash
python3 triager.py \
  --zip triage_collection.zip \
  -c config.yml \
  -o output_directory
```

Search across parsed output:

```bash
python3 triager.py -d output_directory --search "PsExec"
python3 triager.py -d output_directory --search "Invoke-WebRequest" --search-case-sensitive
python3 triager.py -d output_directory --search "Mimikatz" --search-max-hits 50
```

IOC scan, basically searches common IOC names in a file (`iocs.txt` is included in this repository):

```bash
python3 triager.py -d output_directory --find-iocs iocs.txt
python3 triager.py -d output_directory --find-iocs iocs.txt --save-iocs iocs_dir
```

Generate AI-assisted forensic report:

```bash
$env:OPENAI_API_KEY="your_api_key" # Windows
export OPENAI_API_KEY="your_api_key" # Linux

python3 triager.py -d output_directory --ai
```

This produces `ai_forensic_report.md` inside the output directory. If the API key is set, `Triager` will query OpenAI. If not, the report will contain only the data that can be pasted into a LLM.

**Use this with caution to not expose sensitive information.**

The generated report includes:

* Executive summary
* Suspected activity timeline
* Suspicious commands, binaries, and paths
* Persistence mechanisms
* Recommended investigative next steps

## Typical workflow example

```bash
python3 triager.py --config config.yml --root /mnt/triage_dir --output out_dir

python3 triager.py -d out_dir --search "schtasks" --search-max-hits 50
python3 triager.py -d out_dir --find-iocs iocs.txt
```

## Current output structure:

```
+---Event logs
|   +---APT-Hunter
|   +---Chainsaw
|   +---EvtxECmd
|   \---Hayabusa
+---Evidence of execution
|   +---AmCache
|   |   +---AmCache-EvilHunter
|   |   \---AmcacheParser
|   +---Prefetch
|   +---SRUM
|   |   \---SrumECmd
|   +---WER
|   \---WindowsDefenderDetection
+---File system artifacts
|   +---LogFile
|   +---MFT
|   +---RecycleBin
|   \---USNJournal
+---Meta
+---Persistence
|   +---ScheduledTasks
|   \---WMI
+---Registry
|   +---BamDam
|   +---Shimcache
|   \---USB
\---User artifacts
    +---BrowserHistory
    +---Certutil
    +---JumpLists
    +---MUICache
    +---NotepadFiles
    +---NTUSER_Artifacts
    +---PSReadLine
    +---RDPCache
    +---RecentLnk
    +---Shellbags
    +---Thumbnails
    +---UserAssist
    \---Win10Timelines
```

# Building executables

A `build.sh` script is provided to generate standalone binaries for both Linux and Windows (via Wine).

```bash
chmod +x build.sh
./build.sh
```

# License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
