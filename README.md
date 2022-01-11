# DetectionHistory Parser

This repo contains the open-source Python code of my Windows Defender DetectionHistory parser, and the code packaged into an executable for easy use.

## Command Line Interface

![CLI](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/CLI.PNG?raw=true)

## Artifact Creation Documentation

DetectionHistory files may be created and found on, at the very least, Windows 10 systems. The creation of these files is an afterproduct of Windows Defender's real-time/cloud-delivered protection blocking threats such as Potentially Unwanted Applications (PUAs), viruses, worms, trojans, etc. The user should have these features turned on in the Windows Security app, under Windows Security > Virus and Threat Protection > Virus and Threat Protection Settings:  

![RequiredSettings](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/security%20settings.PNG?raw=true)

When Windows Defender detects one of these threats, the user is presented first with a notification that Defender has detected the file. Whether or not the user actually runs this .exe would not impact the creation of its corresponding DetectionHistory file. A sample notification of what one would see is provided below:

![Noti](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/TestNotification.PNG?raw=true)

At this point, Windows Defender places a DetectionHistory file under [root]\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\[numbered folder]\[File GUID]. As long as the file exists in this directory, Windows Defender will pick it up and display a few details in the "Protection History" tab. This can be found under Windows Security > Virus and Threat Protection > Current Threats/Protection History. If this DetectionHistory file shown here is deleted, the notification would disappear along with it:

![FileAndNoti](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/file%20and%20protection%20history.PNG?raw=true)

## Artifact Structure Documentation

For clarity and reader accessibility, this documentation will describe the contents of the DetectionHistory file, "8CC4BE3D-8D3F-4952-9953-F24EB6638A37", located in this repo.

*First Section*

![FileBegin]()

The file begins with a header, '0x0800000008', taking up the first 5 bytes in every known scenario. The parser takes this into account and will move on from the current file if the bytes don't match this header. More complicated is the file GUID- interestingly, the first 3 numbers (seperated by dashes) have their endianness swapped, while the remaining two numbers are unmodified. The GUID does not appear anywhere else on the host system that I have found. It may just be used to generate the DetectionHistory filename. Following this, we begin to see some real information. Each key/value pair is delimited by an ASCII colon/'0x3A' byte, making it easy differentiating field names from their values. While the purpose of "Magic Version" is unknown, we do see the threat name that would have been presented to the user in the original Windows Defender notification (in this case, Trojan:Win32/Ulthar A!ml).

![firsttransition]()

Moving on, we see the same structure continued, until we are presented with the file name which Windows Defender detected the threat from. While this is useful information, it is not delimited with a colon- rather, empty space with one or two bytes in between that serve to mark the beginning of some value. This "file" field serves as a transition into how the file's information is stored in its next major section.

To summarize, the available data from the first section is as follows:

-  DetectionHistory GUID
-  Magic Version
-  Threat Type / Threat Name
-  File Name

*Second Section*

This is the biggest section of the DetectionHistory file.


## Parser Documentation

The files parsed by this application may be found on any Windows system, if they exist, under [root]\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\[numbered folder]\[File GUID]

###
NOTES
###

- The file header should be of the form: b'0800000008', or else it is not a valid DetectionHistory file.

- Immediately following the file header and before the first mention of "Magic Version", the GUID of the file is given in Big-Endian(?) representation, capped off by a b'24' at the end, signaling the end of the GUID and beginning of the DetectionHistory data.

- ThreatTrackingStartTime and all other timestamps are in FILETIME structure (UTC)

- Most hex numbers in this file are stored with a swapped endianness.
