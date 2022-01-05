import sys
import os
import json
import binascii
import re
from datetime import datetime, timedelta
import time
from typing import final
sys.path.append("./")

def parse_header_and_guid(file):
    header = file.read(6) # 6 = known DetectionHistory header size
    if header != b'\x08\x00\x00\x00\x08\x00': # check file header against known valid DetectionHistory file header
        sys.exit("Invalid DetectionHistory file!")
    file.read(18) # skipping over some zeroes, and an unknown 3-byte sequence between offset 08-0A
    guid_oct = list()
    guid_oct.append(binascii.hexlify(file.read(4)))
    guid_oct.append(binascii.hexlify(file.read(2)))
    guid_oct.append(binascii.hexlify(file.read(2)))
    guid_oct.append(binascii.hexlify(file.read(2))) # this hex is not flipped in file data
    guid_oct.append(binascii.hexlify(file.read(6))) # this hex is not flipped in file data
    
    # HANDLE GUID HERE
    oct_count = 0
    while oct_count<=2:
        oct = guid_oct[oct_count]
        newlist = [oct[i:i+2] for i in range(0, len(oct), 2)]
        newlist.reverse()
        guid_oct[oct_count] = b''.join(newlist)
        oct_count=oct_count+1

    guid_final = (guid_oct[0].decode('utf-8')+"-"
        +guid_oct[1].decode('utf-8')+"-"
        +guid_oct[2].decode('utf-8')+"-"
        +guid_oct[3].decode('utf-8')+"-"
        +guid_oct[4].decode('utf-8'))

    return guid_final


def parse_filetime(file):
    filetime = ""
    exponent = 15
    hex_index = 0
    filetime_nanoseconds = 0

    file.read(4) # skip ahead known distance between "Time" field and FILETIME timestamp
    filetime = file.read(8)
    filetime = binascii.hexlify(filetime)
    filetime = [filetime[i:i+2] for i in range(0, len(filetime), 2)] # need to swap endianness of filetime
    filetime.reverse()
    filetime = b''.join(filetime)
    filetime_list = [int("0x"+(filetime[i:i+1].decode('utf-8')),16) for i in range(0, len(filetime), 1)] # python hex converts it wrong, so we do it manually
    while exponent>=0: # manual hex conversion
        print(pow(16,exponent))
        filetime_nanoseconds += filetime_list[hex_index]*(pow(16,exponent))
        hex_index += 1
        exponent += -1
    filetime_epoch = timedelta(microseconds=float(filetime_nanoseconds/10)) # time represented in hundreds of nanoseconds
    filetime_date = datetime(1601, 1, 1)+filetime_epoch # FILETIME begins on Jan 1, 1601
    return filetime_date.strftime("%m-%d-%Y %H:%M:%S")


def parse_unmapped_value(file):
    # This needs to be its own function, as decoding bytes of high hex vals can result in unmapped chars. We will also convert to Int64
    # this function should also parse threat id into Int64 based on windows specs
    # https://docs.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection?view=windowsserver2022-ps
    # https://www.windows-security.org/c328023496d244ced5d0c4445e4f1806/threat-id-exclusions
    unmapped_val = ""
    file.read(4) # skip ahead a general known distance between field name and hex value
    unmapped_val = binascii.hexlify(file.read(5))
    print(unmapped_val)
    # maybe do a forward lookup for empty bytes?
    # if \x00\x00
    #    # seek backwards and check if \xANY\x00
    #    # if that, then switch to null data mode
    return unmapped_val


def parse_detection_history(my_args):

    filepath = my_args["filepath"]
    parsed_value_dict = dict()

    # DEFINE MODES
    KEY_READ_MODE = b'\x00'
    VALUE_READ_MODE = b'\x01'
    NULL_DATA_MODE = b'\x02'
    CURRENT_MODE = KEY_READ_MODE
    LAST_READ_MODE = b'\xFF'
    # DEFINE SECTIONS
    MAGIC_VERSION_SECTION = b'\x04'
    GENERAL_SECTION = b'\x05'
    NEAREST_EOF_SECTION = b'\x06'
    # EXTRA NEEDED VARIABLES
    EOF_SECTION_KEYS = ["HostMachineOrUser","SpawningProcess","SecurityGroup"]
    CURRENT_EOF_SECTION_KEY = -1

    with open(filepath, 'rb') as f:
        parsed_value_dict["GUID"] = parse_header_and_guid(f)
        f.read(8) # skipping over some empty space
        temp_key = ""

        while True:
            while MAGIC_VERSION_SECTION:
                chunk = f.read(2)
                if CURRENT_MODE==KEY_READ_MODE: 
                    print("Key read mode")
                    if chunk==b'\x3A\x00': # first few sections are delimited by a Windows-1252 colon rather than multiple \x00 bytes
                        print("Switching to Value Read Mode")
                        temp_key = re.sub("\x00", "", temp_key)
                        parsed_value_dict[temp_key] = "" # we will reset temp_key after setting the value
                        CURRENT_MODE = VALUE_READ_MODE 
                    else:
                        temp_key = temp_key+chunk.decode('windows-1252')
                        print(chunk)
                        print(temp_key)
                        print("Checking if file in temp_key...")
                        if "f\x00i\x00l\x00e" in temp_key: # file key/value pair signifies end of values delimited by colons (or \x3A)
                            print("End of section detected!")
                            temp_key = re.sub("\x00", "", temp_key)
                            parsed_value_dict[temp_key] = "" # make sure "file" key gets assigned
                            CURRENT_MODE = VALUE_READ_MODE
                            MAGIC_VERSION_SECTION = 0 # break out of this section
                            f.read(16) # skip some zeroes to next section
                elif CURRENT_MODE==VALUE_READ_MODE:
                    print("Value read mode")
                    if chunk==b'\x00\x00': # if chunk to be read is empty
                        if f.read(2)==b'\x00\x00': # if next chunk empty as well
                            print("Switching to Null Data Mode")
                            parsed_value_dict[temp_key] = re.sub("\x00", "", parsed_value_dict[temp_key]) # finalize value
                            temp_key = "" # reset temp key for next run
                            CURRENT_MODE=NULL_DATA_MODE
                    else:
                        parsed_value_dict[temp_key] = parsed_value_dict[temp_key] + str(chunk.decode('windows-1252'))
                elif CURRENT_MODE==NULL_DATA_MODE:
                    print("Null data mode")
                    if len(re.sub(r'\W+', '', chunk.decode('windows-1252')))>=1: # regex function removes all non-alphanum characters
                        chunk = chunk+f.read(2) # double check if there are 2 alphanum chars in sequence. sometimes there are isolated, irrelevant hex values in file which are encodable chars
                        if len(re.sub(r'\W+', '', chunk.decode('windows-1252')))>=2: 
                            print(chunk.decode('windows-1252'))
                            temp_key = temp_key+chunk.decode('windows-1252')
                            print("Switching to Key Read Mode")
                            CURRENT_MODE = KEY_READ_MODE

            while GENERAL_SECTION:
                chunk = f.read(2)
                if not chunk:
                    print("End of section or file detected. Moving on...")
                    print(parsed_value_dict)
                    GENERAL_SECTION = 0 # break out of this section
                    break
                elif CURRENT_MODE==NULL_DATA_MODE:
                    if len(re.sub(r'\W+', '', chunk.decode('windows-1252')))>=1: # regex function removes all non-alphanum characters
                        chunk = chunk+f.read(2) # double check if there are 2 alphanum chars in sequence. sometimes there are isolated, irrelevant hex values in file which are encodable chars
                        if len(re.sub(r'\W+', '', chunk.decode('windows-1252')))>=2: 
                            print(chunk.decode('windows-1252'))
                            if LAST_READ_MODE==KEY_READ_MODE: # we need to switch back and forth between key and value reading
                                print("Switching to Value Read Mode")
                                parsed_value_dict[temp_key] = parsed_value_dict[temp_key] + str(chunk.decode('windows-1252'))
                                CURRENT_MODE=VALUE_READ_MODE
                            else:
                                print("Switching to Key Read Mode")
                                temp_key = temp_key+chunk.decode('windows-1252')
                                CURRENT_MODE=KEY_READ_MODE
                    elif chunk==b'\x0A\x00' or chunk==b'\x00\x0A':
                        print("End of General Section!")
                        f.read(10) # skip over unneeded section of hex, delimited by "\x0A"
                        GENERAL_SECTION = 0 # break out of this section
                else: # Applies to KEY_READ or VALUE_READ mode
                    if chunk==b'\x00\x00': # Check to switch to NULL_MODE must happen in either KEY_READ or VALUE_READ mode
                        print("Switching to Null Data Mode")           
                        if CURRENT_MODE==KEY_READ_MODE:
                            temp_key = re.sub("\x00", "", temp_key)
                            if "Magic." in temp_key[0:6]:
                                print("Extraneous \"Magic Version\" key detected! Continuing...")
                                temp_key = "" # reset for next KEY_READ_MODE run
                                LAST_READ_MODE = VALUE_READ_MODE # skip over this key, read in next key
                            elif "Time" in temp_key:
                                parsed_value_dict[temp_key] = parse_filetime(f)
                                temp_key = "" # reset for next KEY_READ_MODE run
                                LAST_READ_MODE = VALUE_READ_MODE # value just set, read in next key
                            elif "ThreatTrackingThreatId" in temp_key or "ThreatTrackingSize" in temp_key:
                                parsed_value_dict[temp_key] = parse_unmapped_value(f)   
                                temp_key = "" # reset for next KEY_READ_MODE run
                                LAST_READ_MODE = VALUE_READ_MODE # value just set, read in next key                         
                            else:
                                parsed_value_dict[temp_key] = "" # we will reset temp_key after setting the value in VALUE_READ_MODE
                                LAST_READ_MODE = KEY_READ_MODE
                            CURRENT_MODE = NULL_DATA_MODE
                        elif CURRENT_MODE==VALUE_READ_MODE:
                            final_value = re.sub("\x00", "", parsed_value_dict[temp_key])
                            if "Threat" in final_value[0:6] or "regkey" in final_value[0:6]:
                                print("Irregularity in file caused error in parsing: reassigning keys...")
                                print(temp_key)
                                print(final_value)
                                parsed_value_dict[temp_key] = "" # reset extraneous value for temp_key
                                parsed_value_dict[final_value] = "" # this value containing "Threat" or "regkey" should have been a key
                                temp_key = final_value # set the final_value to the new key
                                LAST_READ_MODE = KEY_READ_MODE # for that key, collect the next value
                                if "ThreatTrackingThreatId" in temp_key:
                                    parsed_value_dict[temp_key] = parse_unmapped_value(f)   
                                    temp_key = "" # reset for next KEY_READ_MODE run
                                    LAST_READ_MODE = VALUE_READ_MODE
                            else:
                                parsed_value_dict[temp_key] = final_value # finalize value
                                LAST_READ_MODE = VALUE_READ_MODE # when working as intended
                                temp_key = "" # reset temp key for next KEY_READ_MODE
                            print(parsed_value_dict)
                            CURRENT_MODE = NULL_DATA_MODE
                    elif CURRENT_MODE==KEY_READ_MODE:
                        print("Key read mode")
                        temp_key = temp_key+chunk.decode('windows-1252')
                        print(temp_key)
                    elif CURRENT_MODE==VALUE_READ_MODE:
                        print("Value read mode")
                        parsed_value_dict[temp_key] = parsed_value_dict[temp_key] + str(chunk.decode('windows-1252'))
                        print(parsed_value_dict[temp_key])

            while NEAREST_EOF_SECTION:
                chunk = f.read(2)
                print(chunk)
                if not chunk:
                    print("EOF detected. Closing...")
                    print(parsed_value_dict)
                    NEAREST_EOF_SECTION = 0 # break out of this section
                    break
                elif CURRENT_MODE==NULL_DATA_MODE:
                    print("Null Data Mode") 
                    if chunk==b'\x0A\x00' or chunk==b'\x00\x0A': # track lines with "\x0A" bytes. This byte delimits an unknown hex sequence that (for now) we can skip
                        f.read(10)
                        continue
                    try:
                        if len(re.sub(r'\W+', '', chunk.decode('windows-1252')))>=1: # regex function removes all non-alphanum characters
                            chunk = chunk+f.read(2) # double check if there are 2 alphanum chars in sequence. sometimes there are isolated, irrelevant hex values in file which are encodable chars
                            if len(re.sub(r':(?=..(?<!\d:\d\d))|[^a-zA-Z0-9 ](?<!:)', '', chunk.decode('windows-1252')))>=2:
                                print("Switching to Value Read Mode")
                                print(chunk.decode('windows-1252'))
                                CURRENT_EOF_SECTION_KEY=CURRENT_EOF_SECTION_KEY+1 
                                parsed_value_dict[EOF_SECTION_KEYS[CURRENT_EOF_SECTION_KEY]] = chunk.decode('windows-1252')
                                CURRENT_MODE=VALUE_READ_MODE
                    except UnicodeDecodeError as e:
                        print(f"!!{e}!! caught for chunk {chunk} : assuming unreadable hex pattern and skipping...")
                    except UnicodeEncodeError as e:
                        print(f"!!{e}!! caught for chunk {chunk} : assuming unreadable hex pattern and skipping...")
                        f.read(4)
                elif CURRENT_MODE==VALUE_READ_MODE:
                    print("Value Read Mode")                     
                    if chunk==b'\x00\x00': # Check to switch to NULL_MODE must happen in either KEY_READ or VALUE_READ mode
                        print("Switching to Null Data Mode")
                        parsed_value_dict[EOF_SECTION_KEYS[CURRENT_EOF_SECTION_KEY]] = re.sub("\x00", "", parsed_value_dict[EOF_SECTION_KEYS[CURRENT_EOF_SECTION_KEY]])
                        print(parsed_value_dict)           
                        CURRENT_MODE=NULL_DATA_MODE
                    else:
                        parsed_value_dict[EOF_SECTION_KEYS[CURRENT_EOF_SECTION_KEY]] += chunk.decode('windows-1252')
                        print(chunk.decode('windows-1252'))
            break 
                        


def main():
    args = dict()
    args["filepath"] = "D:\\klepserforensics\\defender-detectionhistory-parser\\8CC4BE3D-8D3F-4952-9953-F24EB6638A37"
    #args["filepath"] = "D:\\klepserforensics\\defender-detectionhistory-parser\\22CC8FCE-98AB-4B7F-8ABB-821FBF6BC4A4"
    
    parse_detection_history(args)
    #parse_filetime(b'f7a047fe7b31d701')

if __name__ == "__main__":
    main()
