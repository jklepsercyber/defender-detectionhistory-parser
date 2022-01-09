The files parsed by this application may be found on any Windows system, if they exist, under [root]\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory\\[numbered folder]\\[File GUID]

###
NOTES
###

- The file header should be of the form: b'0800000008', or else it is not a valid DetectionHistory file.

- Immediately following the file header and before the first mention of "Magic Version", the GUID of the file is given in Big-Endian(?) representation, capped off by a b'24' at the end, signaling the end of the GUID and beginning of the DetectionHistory data.

- ThreatTrackingStartTime and all other timestamps are in FILETIME structure (UTC)

- Most hex numbers in this file are stored with a swapped endianness.
