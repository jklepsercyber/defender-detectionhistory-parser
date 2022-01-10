# DetectionHistory Parser

Lorem Ipsum

## Command Line Interface

![]()

## Artifact Creation Documentation

DetectionHistory files may be created and found on, at the very least, Windows 10 systems. The creation of these files is an afterproduct of Windows Defender's real-time/cloud-delivered protection blocking threats such as Potentially Unwanted Applications (PUAs), viruses, worms, trojans, etc. The user should have these features turned on in the Windows Security app, under Windows Security > Virus and Threat Protection > Virus and Threat Protection Settings:  

![]()

When Windows Defender detects one of these threats, the user is presented first with a notification that Defender has detected the file. Whether or not the user actually runs this .exe would not impact the creation of its corresponding DetectionHistory file. A sample notification of what one would see is provided below:

![]()

At this point, if the DetectionHistory file is in this directory, Windows Defender will pick it up and display a few details in the "Protection History" tab, under Windows Security > Virus and Threat Protection > Current Threats/Protection History. If this DetectionHistory file shown here is deleted, the notification would disappear along with it:

![]()


The files exist under [root]\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\[numbered folder]\[File GUID]. An example of what the directory might look like is provided below:


## Parser Documentation

The files parsed by this application may be found on any Windows system, if they exist, under [root]\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\[numbered folder]\[File GUID]

###
NOTES
###

- The file header should be of the form: b'0800000008', or else it is not a valid DetectionHistory file.

- Immediately following the file header and before the first mention of "Magic Version", the GUID of the file is given in Big-Endian(?) representation, capped off by a b'24' at the end, signaling the end of the GUID and beginning of the DetectionHistory data.

- ThreatTrackingStartTime and all other timestamps are in FILETIME structure (UTC)

- Most hex numbers in this file are stored with a swapped endianness.