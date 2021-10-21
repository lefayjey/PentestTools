#!/usr/bin/python

import argparse
import os
import io
import re

def format_Data(fHandle):
    fh = io.open(fHandle, 'r')
    SamAccountName = ''
    DistinguishedName = ''
    Hash = ''
    Hashes = []
    try:
        for line in fh:
            #Grab the SamAccountName
            if "SamAccountName" in line:
                stuff = line.split(':')
                SamAccountName = stuff[1].strip()
            #Grab the DistinguishedName
            if "DistinguishedName" in line:
                stuff = line.split(':')
                stuff = line.split(',')
                DistinguishedName = "{0}.{1}".format(stuff[-2].strip().replace('DC=',''),stuff[-1].strip().replace('DC=',''))
            #Grab Hash Line
            if "Hash" in line:
                stuff = line.split(' :')
                Hash += stuff[1].strip()
            #Grab Hash Line
            if "                       " in line:
                Hash += line.strip()
            if line == '\n':
                Hashes.append(re.sub(r'\*.*\*',"*{0}${1}$spn*$".format(SamAccountName,DistinguishedName), Hash))
                SamAccountName = ''
                DistinguishedName = ''
                Hash = ''
                pass
    except:
        pass
    return Hashes


parser = argparse.ArgumentParser(description='Parser of Kerberoast output from Invoke-Kerberoast')

parser.add_argument('-f', action="store", dest="inputHandle", required=True)
parser.add_argument('-w', action="store", dest="outputHandle")

parsed = parser.parse_args()

if(os.path.isfile(parsed.inputHandle)):
    print("Opening file: {0}").format(parsed.inputHandle)
    output = format_Data(parsed.inputHandle)
    if parsed.outputHandle:
        fOutput = open(parsed.outputHandle, 'w')
        for element in output:
            fOutput.write(element)
            fOutput.write('\n')
        fOutput.close()
        print("Hashes written to: {0}".format(parsed.outputHandle))
    else:
        for element in output:
            print(element)
            print('\n')
else:
    print("Error opening file: {0}").format(parsed.inputHandle)
    exit()
