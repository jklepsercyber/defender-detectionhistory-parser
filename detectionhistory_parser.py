import sys
import os
import json
import binascii
sys.path.append("./")

def parse_detection_history(my_args):
    filepath = my_args["filepath"]
    with open(filepath, 'rb') as f:
        for line in f:
            print(line.read())
        decoded_line = ""
        for seg in f:
            try:
                print(seg)
                decoded_line = binascii.hexlify(seg)
                print(decoded_line)
                print("\n")
            except UnicodeDecodeError as e:
                print (f"{type(e)} : {e}")
                print("\n")


def main():
    args = dict()
    args["filepath"] = "D:\\klepserforensics\\detectionhistory-parser\\22CC8FCE-98AB-4B7F-8ABB-821FBF6BC4A4"
    parse_detection_history(args)

if __name__ == "__main__":
    main()
