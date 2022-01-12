# DetectionHistory Parser

This repo contains the open-source Python code of my Windows Defender DetectionHistory parser, and the code packaged into an executable for easy use.

## Command Line Interface

![CLI](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/CLI.PNG?raw=true)

The DetectionHistory parser provides a variety of options, designed to tailor the experience to your needs. The greedy option, is designed to pick up files outside of Windows' naming convention that may have been renamed for storage or other purposes. It is advised to simply either point the parser at the DetectionHistory folder listed in **Artifact Creation Documentation** with **-r** enabled, or copy the unmodified files out to a directory of your choice. 

## Artifact Creation Documentation

DetectionHistory files may be created and found on, at the very least, Windows 10 systems. The creation of these files is an afterproduct of Windows Defender's real-time/cloud-delivered protection(RTP) blocking threats such as Potentially Unwanted Applications (PUAs), viruses, worms, trojans, etc. The user should have these features turned on in the Windows Security app, under Windows Security > Virus and Threat Protection > Virus and Threat Protection Settings:  

![RequiredSettings](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/security%20settings.PNG?raw=true)

When Windows Defender detects one of these threats, the user is presented first with a notification that Defender has detected the file. Whether or not the user actually runs this .exe would not impact the creation of its corresponding DetectionHistory file. A sample notification of what one would see is provided below:

![Noti](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/TestNotification.PNG?raw=true)

At this point, Windows Defender places a DetectionHistory file under **[root]\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\[numbered folder]\[File GUID]**. As long as the file exists in this directory, Windows Defender will pick it up and display a few details in the "Protection History" tab. This can be found under Windows Security > Virus and Threat Protection > Current Threats/Protection History. If this DetectionHistory file shown here is deleted, the notification would disappear along with it:

![FileAndNoti](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/file%20and%20protection%20history.PNG?raw=true)

A great resource for attempting to generate these notifications on your own system can be found [here](https://demo.wd.microsoft.com/). Included are benign PUA and malware files designed to attract Windows Defender RTP/Defender ATP's attention.

## Artifact Structure Documentation

For clarity and reader accessibility, this documentation will describe the contents of the DetectionHistory file, "8CC4BE3D-8D3F-4952-9953-F24EB6638A37", located in this repo.

**First Section**

![FileBegin](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/filebegin.png)

The file begins with a header, '0x0800000008', taking up the first 5 bytes in every known scenario. The parser takes this into account and will move on from the current file if the bytes don't match this header. More complicated is the DetectionID GUID- interestingly, the first 3 numbers (seperated by dashes) have their endianness swapped, while the remaining two numbers are unmodified. The DetectionID is used by Windows' API to keep track of each threat on the backend. Following this, we see a familar dictionary-like style of information. Each key/value pair is delimited by an ASCII colon/'0x3A' byte, making it easy differentiating field names from their values. While the purpose of "Magic Version" is unknown, we do see the threat name that would have been presented to the user in the original Windows Defender notification (in this case, Trojan:Win32/Ulthar.A!ml).

![threatstatusid](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/threatstatusid.png)

At the same hex offset, '0000000F0', in every DetectionHistory file, the current ThreatStatusID of the given DetectionID can be found. The ID has many different values which represent any user action taken on the threat, such a quarantine, remove, allow, etc. As the user takes actions, the DetectionHistory file is updated with the corresponding ThreatStatusID. More information is available for each ThreatStatus [on Microsoft's MSFT_MpThreatDetection class documentation.](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpthreatdetection) 

![firsttransition](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/magicvers_to_general.png)

Moving on, we see the same structure continued, until we are presented with the file name which Windows Defender detected the threat from. While this is useful information, it is not delimited with a colon- rather, empty space with one or two bytes in between that serve to mark the beginning of some value. This "file" field serves as a transition into how the file's information is stored in its next major section.

To summarize, the available data from the first section is as follows:

-  DetectionHistory GUID
-  Magic Version
-  ThreatStatusID
-  Threat Type / Threat Name
-  File Name

**Second Section**

This is the biggest section of the DetectionHistory file. The majority of its values are plaintext hash values, registry keys or identifiers. Some field names are followed with nearly empty values, only containing one or two bytes, whose meaning is unknown. Some values, which I will go over, are stored as endian-swapped hexademical numbers. 

![secondsection](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/secondsection.png)

The large box shows the general form of data in this section- A field name, seperated by empty space as the "file" field was in the last section, followed by some plaintext or hexadecimal value. A field with a hexadecimal value is shown under ThreatTrackingStartTime, shown in the lower set of boxes, and also the only timestamp value included in the file. The timestamp is stored in FILETIME format, in the UTC timezone. As such, a custom function was written into the parser to perform these operations. The operations include an endian-swap and manual hex conversion. 

![threatsize](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/size.PNG)
![threatid](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/id.PNG)

Some other hexadecimal values simply need to be endian-swapped and converted to integers. For example, ThreatTrackingSize and ThreatTrackingThreatID provide the size and ThreatID of the detected threat in hex, respectively. The ThreatID is believed to be a way for Microsoft to internally track threats detected via Windows Defender ATP. This is because not only is there evidence in Windows EVTX of Windows Defender uploading files to Microsoft for further analysis (Windows-Defender/Operational Event ID 2050), there is evidence of the Threat ID being included in the Windows Defender detection Event (Windows-Defender/Operational Event ID 1116) corresponding to this DetectionHistory file. 

![evtx_1116_and_2050](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/evtx_1116_2050.PNG)

While there is not much documentation on the use of ThreatIDs, [Windows 10 and Server 2019 Powershell appears to include a way to use ThreatIDs to retrieve previous Windows Defender detections.](https://docs.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection?view=windowsserver2019-ps) On a side note, the Threat ID pictured above was also included in the first section (without its accompanying field name), right after the file header (in this case, '0x9D170480'). The reason for this may only serve for Windows to have a place to easily retrieve the ThreatID. Can you find it?

![regkey](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/regkey.png)

The contents of the second section may differ between different threat types (PUAs, Trojan, Virus, Worm). An example in DetectionHistory files generated from PUAs is the inclusion of the PUA's "regkey" and "uninstall" registry key fields, which, if they exist on the system, would again provide another source of evidence that the threat once existed on the host machine. The "regkey" field has been observed to provide an SID, a useful piece of information in tracking who or what accounts may have tried to introduce threats on a machine. In threats other than PUAs, even empty regkey fields are not included in the DetectionHistory file. 

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

![thirdsection](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/thirdsection.png)

The beginning of the third and final section is delimited by a '\0x0A\0x00' byte sequence, immediately followed by the same timestamp used in ThreatTrackingStartTime. This is visible in the box on line 00000730. The sequence does not decode to a ASCII character and is used nowhere else, so this makes it easy for the parser to tell when the section begins. The reason that the timestamp is included again here is unknown.

There are a maximum of three fields here that we may parse out, shown above and boxed on the right. The field names are not included, so information has been taken from the live system view of the artifact and documentation to provide the clearest results. The first two values, which reference a desktop user and "explorer.exe", are known to represent the domain user and the spawning process, or in other words, the process used to launch the identified threat. This could be useful when identifying if certain pieces of malware were run from the command line, and then detected by Defender RTP. The third field is of an unknown purpose, as it is not always present through each DetectionHistory file. Given the value of "NT AUTHORITY/SYSTEM", it is likely that this represents the security group the user account belongs to (through analysis of the user SID).

To summarize, the available data from the second section is as follows:
-  User
-  SpawningProcess
-  SecurityGroup

## Live System Viewing

If you are curious about how Windows stores this data in a live, API-interactive format, the MSFT_MpThreatDetection class, viewable from PowerShell, displays data from each DetectionHistory file as well.

![livesystem](https://github.com/jklepsercyber/defender-detectionhistory-parser/blob/develop/images/liveview.PNG)

Of course, this is only available as long as the DetectionHistory files exist in their respective directory.

## Conclusion

This parser is a continued project, to be updated with more features, fixed issues, and better documentation as time goes on. Please let me know if you have any questions or concerns regarding this repo. Special thanks to those listed here for their continued support throughout the process:

-  SANS Institute
-  Chad Tilbury
-  David Nides

