# uiScribe

## v1.4.13
### Updated on 2026-Feb-22

## About
uiScribe updates the System Log page to show log files created by Scribe (syslog-ng). Requires [**Scribe**](https://github.com/cynicastic/scribe)
Support for Scribe can be found here: [Scribe on SNBForums](https://www.snbforums.com/threads/scribe-syslog-ng-and-logrotate-installer.55853/)

uiScribe is free to use under the [GNU General Public License version 3](https://opensource.org/licenses/GPL-3.0) (GPL 3.0).

## Supported firmware versions
You must be running firmware Merlin 384.15/384.13_4 (or later) [Asuswrt-Merlin](https://asuswrt.lostrealm.ca/)

## Installation
Using your preferred SSH client/terminal, copy and paste the following command, then press Enter:

```sh
/usr/sbin/curl --retry 3 "https://raw.githubusercontent.com/AMTM-OSR/uiScribe/master/uiScribe.sh" -o "/jffs/scripts/uiScribe" && chmod 0755 /jffs/scripts/uiScribe && /jffs/scripts/uiScribe install
```

## Usage
### WebUI
uiScribe replaces the System Log page in the WebUI.

To launch the uiScribe menu after installation, use:
```sh
uiScribe
```

### Command Line
If this does not work, you will need to use the full path:
```sh
/jffs/scripts/uiScribe
```

## Screenshots

![WebUI](https://puu.sh/GRzoX/b2a7129ae7.png)

![CLI](https://puu.sh/GRzco/73d693ecb2.png)

## Help
Please post about any issues and problems here: [Asuswrt-Merlin AddOns on SNBForums](https://www.snbforums.com/forums/asuswrt-merlin-addons.60/?prefix_id=24)
