import sys
import os
import json
import binascii
import re
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
    # DEFINE SECTIONS
    MAGIC_VERSION_SECTION = b'\x04'
    GENERAL_SECTION = b'\x05'

    with open(filepath, 'rb') as f:
        parsed_value_dict["GUID"] = parse_header_and_guid(f)
        f.read(8) # skipping over some empty space

        while True:
            temp_key = ""
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
                            MAGIC_VERSION_SECTION = 0 # break out of this section
                elif CURRENT_MODE==VALUE_READ_MODE:
                    print("Value read mode")
                    chunk = f.read(2)
                    if chunk==b'\x00\x00': # if chunk to be read is empty
                        print("Empty chunk detected")
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
                        print(chunk.decode('windows-1252'))
                        temp_key = temp_key+chunk.decode('windows-1252')
                        print("Switching to Key Read Mode")
                        CURRENT_MODE = KEY_READ_MODE
            while GENERAL_SECTION:
                GENERAL_SECTION = 0
                pass
            chunk = f.read(2)
            if not chunk:
                print("EOF detected. Closing...")
                print(parsed_value_dict)
                break
                        


def main():
    args = dict()
    args["filepath"] = "D:\\klepserforensics\\detectionhistory-parser\\22CC8FCE-98AB-4B7F-8ABB-821FBF6BC4A4"
    parse_detection_history(args)

if __name__ == "__main__":
    main()
