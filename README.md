# DetectionHistory Parser

This repo contains the open-source Python code of my Windows Defender DetectionHistory parser, and the code packaged into an executable for easy use.

## Command Line Interface

![CLI](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/CLI.PNG?raw=true)

## Artifact Creation Documentation

DetectionHistory files may be created and found on, at the very least, Windows 10 systems. The creation of these files is an afterproduct of Windows Defender's real-time/cloud-delivered protection(RTP) blocking threats such as Potentially Unwanted Applications (PUAs), viruses, worms, trojans, etc. The user should have these features turned on in the Windows Security app, under Windows Security > Virus and Threat Protection > Virus and Threat Protection Settings:  

![RequiredSettings](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/security%20settings.PNG?raw=true)

When Windows Defender detects one of these threats, the user is presented first with a notification that Defender has detected the file. Whether or not the user actually runs this .exe would not impact the creation of its corresponding DetectionHistory file. A sample notification of what one would see is provided below:

![Noti](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/TestNotification.PNG?raw=true)

At this point, Windows Defender places a DetectionHistory file under [root]\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\[numbered folder]\[File GUID]. As long as the file exists in this directory, Windows Defender will pick it up and display a few details in the "Protection History" tab. This can be found under Windows Security > Virus and Threat Protection > Current Threats/Protection History. If this DetectionHistory file shown here is deleted, the notification would disappear along with it:

![FileAndNoti](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/file%20and%20protection%20history.PNG?raw=true)

A great resource for attempting to generate these notifications on your own system can be found [here](https://demo.wd.microsoft.com/). Included are benign PUA and malware files designed to attract Windows Defender RTP/Defender ATP's attention.

## Artifact Structure Documentation

For clarity and reader accessibility, this documentation will describe the contents of the DetectionHistory file, "8CC4BE3D-8D3F-4952-9953-F24EB6638A37", located in this repo.

**First Section**

![FileBegin](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/filebegin.png)

The file begins with a header, '0x0800000008', taking up the first 5 bytes in every known scenario. The parser takes this into account and will move on from the current file if the bytes don't match this header. More complicated is the file GUID- interestingly, the first 3 numbers (seperated by dashes) have their endianness swapped, while the remaining two numbers are unmodified. The GUID does not appear anywhere else on the host system that I have found. It may just be used to generate the DetectionHistory filename. Following this, we begin to see some real information. Each key/value pair is delimited by an ASCII colon/'0x3A' byte, making it easy differentiating field names from their values. While the purpose of "Magic Version" is unknown, we do see the threat name that would have been presented to the user in the original Windows Defender notification (in this case, Trojan:Win32/Ulthar.A!ml).

![firsttransition](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/magicvers_to_general.png)

Moving on, we see the same structure continued, until we are presented with the file name which Windows Defender detected the threat from. While this is useful information, it is not delimited with a colon- rather, empty space with one or two bytes in between that serve to mark the beginning of some value. This "file" field serves as a transition into how the file's information is stored in its next major section.

To summarize, the available data from the first section is as follows:

-  DetectionHistory GUID
-  Magic Version
-  Threat Type / Threat Name
-  File Name

**Second Section**

This is the biggest section of the DetectionHistory file. The majority of its values are plaintext hash values, registry keys or identifiers. Some field names are followed with nearly empty values, only containing one or two bytes, whose meaning is unknown. Some values, which I will go over, are stored as endian-swapped hexademical numbers. 

![secondsection](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/secondsection.png)

The large box shows the general form of data in this section- A field name, seperated by empty space as the "file" field was in the last section, followed by some plaintext or hexadecimal value. A field with a hexadecimal value is shown under ThreatTrackingStartTime, shown in the lower set of boxes, and also the only timestamp value included in the file. The timestamp is stored in FILETIME format, in the UTC timezone. As such, a custom function was written into the parser to perform these operations. The operations include an endian-swap and manual hex conversion. 

![threatsize](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/size.PNG)
![threatid](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/id.PNG)

Some other hexadecimal values simply need to be endian-swapped and converted to integers. For example, ThreatTrackingSize and ThreatTrackingThreatID provide the size and threat ID of the detected threat in hex, respectively. The Threat ID is believed to be a way for Microsoft to internally track threats detected via Windows Defender ATP. This is because not only is there evidence in Windows EVTX of Windows Defender uploading files to Microsoft for further analysis (Windows-Defender/Operational Event ID 2050), there is evidence of the Threat ID being included in the Windows Defender detection Event (Windows-Defender/Operational Event ID corresponding to this DetectionHistory file. 

![evtx_1116_and_2050](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/evtx_1116_2050.PNG)

While there is not much documentation on the use of Threat IDs, [Windows 10 and Server 2019 Powershell appears to include a way to use Threat IDs to retrieve previous Windows Defender detections.](https://docs.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection?view=windowsserver2019-ps) On a side note, the Threat ID pictured above was also included in the First Section of the file (without its accompanying field name), right after the file header. Can you find it?

![regkey](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/regkey.png)

The contents of the Second Section may differ between different threat types (PUAs, Trojan, Virus, Worm). An example in DetectionHistory files generated from PUAs is the inclusion of the PUA's "regkey" and "uninstall" registry key fields, which, if they exist on the system, would again provide another source of evidence that the threat once existed on the host machine. The "regkey" field has been observed to provide an SID, a useful piece of information in tracking who or what accounts may have tried to introduce threats on a machine. In threats other than PUAs, even empty regkey fields are not included in the DetectionHistory file. 

To summarize, the available data from the second section is as follows:

-  ThreatTrackingId
-  ThreatTrackingSigSeq
-  ThreatTrackingSha256
-  ThreatTrackingStartTime (FILETIME (UTC))
-  ThreatTrackingMD5
-  ThreatTrackingSigSha
-  ThreatTrackingSha1
-  ThreatTrackingSize
-  ThreatTrackingScanFlags
-  ThreatTrackingIsEsuSig
-  ThreatTrackingThreatId
-  ThreatTrackingScanSource
-  ThreatTrackingScanType
-  ThreatTrackingIdList (VARIABLE INCLUSION)
-  regkey (VARIABLE INCLUSION)
-  uninstall (VARIABLE INCLUSION)

**Third Section**

## Parser Documentation

###
NOTES
###

- Most hex numbers in this file are stored with a swapped endianness.
