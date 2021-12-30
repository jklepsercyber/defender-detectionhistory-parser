import sys
import os
import json
import binascii
import re
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
        print(oct)
        newlist = list(binascii.hexlify(oct))
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

    with open(filepath, 'rb') as f:
        parsed_value_dict["GUID"] = parse_header_and_guid(f)
        f.read(8) # skipping over some empty space
        temp_key = ""

        while True:
            while MAGIC_VERSION_SECTION:
                if CURRENT_MODE==KEY_READ_MODE: 
                    print("Key read mode")
                    chunk = f.read(2)
                    if chunk==b'\x3A\x00': # first few sections are delimited by a Windows-1252 colon rather than multiple \x00 bytes
                        print("Switching to Value Read Mode")
                        temp_key = re.sub("\x00", "", temp_key)
                        parsed_value_dict[temp_key] = "" # we will reset temp_key after setting the value
                        print(parsed_value_dict)
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
                    chunk = f.read(2)
                    if chunk==b'\x00\x00': # if chunk to be read is empty
                        if f.read(2)==b'\x00\x00': # if next chunk empty as well
                            print("Switching to Null Data Mode")
                            parsed_value_dict[temp_key] = re.sub("\x00", "", parsed_value_dict[temp_key]) # finalize value
                            temp_key = "" # reset temp key for next run
                            CURRENT_MODE=NULL_DATA_MODE
                    else:
                        parsed_value_dict[temp_key] = parsed_value_dict[temp_key] + str(chunk.decode('windows-1252'))
                        print(chunk)
                        print(parsed_value_dict[temp_key])
                elif CURRENT_MODE==NULL_DATA_MODE:
                    print("Null data mode")
                    chunk = f.read(2)
                    if len(re.sub(r'\W+', '', chunk.decode('windows-1252')))>=1: # regex function removes all non-alphanum characters
                        chunk = chunk+f.read(2) # double check if there are 2 alphanum chars in sequence. sometimes there are isolated, irrelevant hex values in file which are encodable chars
                        if len(re.sub(r'\W+', '', chunk.decode('windows-1252')))>=2: 
                            print(chunk.decode('windows-1252'))
                            temp_key = temp_key+chunk.decode('windows-1252')
                            print("Switching to Key Read Mode")
                            CURRENT_MODE = KEY_READ_MODE

            while GENERAL_SECTION:
                print(parsed_value_dict)
                if not chunk:
                    print("EOF detected. Closing...")
                    print(parsed_value_dict)
                    GENERAL_SECTION = 0 # break out of this section
                    break
                if CURRENT_MODE==NULL_DATA_MODE:
                    print("Null data mode")
                    chunk = f.read(2)
                    print(chunk)
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
                else:
                    chunk = f.read(2)
                    if chunk==b'\x00\x00': # do we need to switch to NULL_DATA_MODE? 
                        print("Switching to Null Data Mode")           
                        if CURRENT_MODE==KEY_READ_MODE:
                            temp_key = re.sub("\x00", "", temp_key)
                            if "Magic." in temp_key[0:6]:
                                print("Extraneous \"Magic Version\" key detected! Continuing...")
                                temp_key = "" # reset for next KEY_READ_MODE run
                                CURRENT_MODE = NULL_DATA_MODE
                                LAST_READ_MODE = VALUE_READ_MODE # skip over this key, read in a new key
                            else:
                                parsed_value_dict[temp_key] = "" # we will reset temp_key after setting the value in VALUE_READ_MODE
                                CURRENT_MODE = NULL_DATA_MODE
                                LAST_READ_MODE = KEY_READ_MODE
                        if CURRENT_MODE==VALUE_READ_MODE:
                            final_value = re.sub("\x00", "", parsed_value_dict[temp_key])
                            if "Threat" in final_value[0:6] or "regkey" in final_value[0:6]:
                                print("Irregularity in file caused error in parsing: reassigning keys...")
                                print(temp_key)
                                print(final_value)
                                parsed_value_dict[temp_key] = ""
                                parsed_value_dict[final_value] = "" # this value containing "Threat" should have been a key
                                temp_key = final_value # set the final_value to the new key
                                LAST_READ_MODE = KEY_READ_MODE # for that key, collect a new value
                            else:
                                parsed_value_dict[temp_key] = final_value # finalize value
                                LAST_READ_MODE = VALUE_READ_MODE # when working as intended
                                temp_key = "" # reset temp key for next KEY_READ_MODE
                            CURRENT_MODE = NULL_DATA_MODE
                    elif CURRENT_MODE==KEY_READ_MODE:
                        print("Key read mode")
                        temp_key = temp_key+chunk.decode('windows-1252')
                        print(chunk)
                        print(temp_key)
                    elif CURRENT_MODE==VALUE_READ_MODE:
                        print("Value read mode")
                        parsed_value_dict[temp_key] = parsed_value_dict[temp_key] + str(chunk.decode('windows-1252'))
                        print(chunk)
                        print(parsed_value_dict[temp_key])

            break 
                        


def main():
    args = dict()
    args["filepath"] = "D:\\klepserforensics\\defender-detectionhistory-parser\\22CC8FCE-98AB-4B7F-8ABB-821FBF6BC4A4"
    parse_detection_history(args)

if __name__ == "__main__":
    main()
