This is Dopamine fork for "AI" devices. It will likely not work on what you have. AI here does not mean Artificial/Apple Intelligence.

## Jailbreaking your "AI" device
> [!WARNING] 
> Not all iOS versions are tested. Currently 18.6 works and 17.5.1 causes a bootloop which would require factory reset to recover.

Before proceeding, ensure you have installed [TrollStore Lite](https://github.com/khanhduytran0/TrollStore/tree/ai#installing-trollstore-lite).

- Download the Dopamine IPA from Releases or compile it yourself
- Install the IPA using TrollStore Lite
- Append boot args `launchd_ignore_boot_task_failure=1 amfi_unrestrict_task_for_pid=1 launchdsuffix=dopamine wdt=-1` (this will be automated later)
- Enable Live File System using `nvram root-live-fs=1 allow-root-hash-mismatch=1` in Terminal
- Open Dopamine app and tap "Jailbreak"
- Reboot your device again. This is to make the kernel pick up the injected launchd

Jailbreak will persist untethered. If you would like to temporarily disable the jailbreak, you can change boot args and remove `launchdsuffix=dopamine`.

<img src="https://github.com/opa334/Dopamine/assets/52459150/ed04dd3e-d879-456d-9aa3-d4ed44819c7e" width="64" />

# Dopamine

A rootless semi-untethered jailbreak for iOS 15.0 - 16.5.1 (arm64e) and iOS 15.0 - 15.8.6 / 16.0 - 16.6.1 (arm64). More details will follow here soon.

Please note that all issues related to version support will be deleted without response.

Official website / download: https://ellekit.space/dopamine/
