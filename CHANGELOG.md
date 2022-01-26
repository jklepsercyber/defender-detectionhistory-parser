# CHANGELOG

## 1.0.1

Features:

  - add `-v, --verbose` command to display additional text output (non-critical warnings).
  - `-v, --version` rebinded to `-z, --version`.
  - Remove `-s, --silent` command, since additional text output now suppressed by default.
  - KAPE target changed to reflect `-s` removal.
  - add Velocidex/Velociraptor target (Thank you to Eduardo Mattos!).

Improvements/Fixes:
  - In Third Section, the double check for valid data now verifies one `\x00` byte exists per Windows-1252 character in a 4-byte sequence. This clears up some cases where invalid data could be picked up.
  - Display "InvalidFile" error for files determined to not be DetectionHistory files.
  - Display "WARNING:" by non-critical warnings for clarity.
  - Display filepath where DetectionHistory file found.
  - More documentation on example commands and warnings.

## 1.0

Features:

  - Initial release!! :)