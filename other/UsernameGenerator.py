#!/usr/bin/python3

import sys
from os import path

print("UsernameGenerator.py - Simple username generator based on a list of name and surname")

if len(sys.argv)!=3:
  print("Usage: python3 UsernameGenerator.py [user file] [output file]")
  exit()

# arguments
user_file=str(sys.argv[1])
output_file=str(sys.argv[2])
print("------------------------------------------------------\nInput file: " + user_file  + "\nOutput file: " + output_file + "\n------------------------------------------------------")

if(path.exists(output_file)):
  print("The file " + output_file + " exists!\nDelete this file before running this script!\n------------------------------------------------------")
  exit()

# file output
output = open(output_file,'w')

nb_user=0

with open(user_file) as fp:
   line = fp.readline().lower()
   while line:
       list_name=line.strip().split()
       if(len(list_name)!=2):
            print("Warning: The line \"" + line.rstrip() + "\" inside " + user_file  + " is not correct. The data must be formatted with this format: [first name] [surname]")
            line = fp.readline().lower()
       else:
         #### Just the Name
         output.write(list_name[1]+'\n')
         #### Just the firstname
         output.write(list_name[0] + '\n')
         #### firstname.name
         output.write(list_name[0] + "." + list_name[1] + '\n')
         #### name.firstname
         output.write(list_name[1] + "." + list_name[0] + '\n')
         #### firstname-name
         output.write(list_name[0] + "-" + list_name[1] + '\n')
         #### name-firstname
         output.write(list_name[1] + "-" + list_name[0] + '\n')
         #### firstnamename
         output.write(list_name[0] + list_name[1] + '\n')
         #### namefirstname
         output.write(list_name[1] + list_name[0] + '\n')
         #### firstname_name
         output.write(list_name[0] + "_" + list_name[1] + '\n')
         #### name_firstname
         output.write(list_name[1] + "_" + list_name[0] + '\n')
         #### F.name
         output.write(list_name[0][0] + "." + list_name[1] + '\n')
         #### N.firstname
         output.write(list_name[1][0] + "." + list_name[0] + '\n')
         #### name.F
         output.write(list_name[1] + "." + list_name[0][0] + '\n')
         #### firstname.N
         output.write(list_name[0] + "." + list_name[1][0] + '\n')
         #### F-name
         output.write(list_name[0][0] + "-" + list_name[1] + '\n')
         #### N-firstname
         output.write(list_name[1][0] + "-" + list_name[0] + '\n')
         #### name-F
         output.write(list_name[1] + "-" + list_name[0][0] + '\n')
         #### firstname-N
         output.write(list_name[0] + "-" + list_name[1][0] + '\n')
         #### Fname
         output.write(list_name[0][0] + list_name[1] + '\n')
         #### Nfirstname
         output.write(list_name[1][0] + list_name[0] + '\n')
         #### nameF
         output.write(list_name[1] + list_name[0][0] + '\n')
         #### firstnameN
         output.write(list_name[0] + list_name[1][0] + '\n')
         #### F_name
         output.write(list_name[0][0] + "_" + list_name[1] + '\n')
         #### N_firstname
         output.write(list_name[1][0] + "_" + list_name[0] + '\n')
         #### name_F
         output.write(list_name[1] + "_" + list_name[0][0] + '\n')
         #### firstname_N
         output.write(list_name[0] + "_" + list_name[1][0] + '\n')
         
         #put maj
         list_name[0]=list_name[0].capitalize()
         list_name[1]=list_name[1].capitalize()
         
         #### Just the Name with uppercase
         output.write(list_name[1]+'\n')
         #### Just the firstname with uppercase
         output.write(list_name[0] + '\n')
         #### firstname.name with uppercase
         output.write(list_name[0] + "." + list_name[1] + '\n')
         #### name.firstname with uppercase
         output.write(list_name[1] + "." + list_name[0] + '\n')
         #### firstname-name with uppercase
         output.write(list_name[0] + "-" + list_name[1] + '\n')
         #### name-firstname with uppercase
         output.write(list_name[1] + "-" + list_name[0] + '\n')
         #### firstnamename with uppercase
         output.write(list_name[0] + list_name[1] + '\n')
         #### namefirstname with uppercase
         output.write(list_name[1] + list_name[0] + '\n')
         #### firstname_name with uppercase
         output.write(list_name[0] + "_" + list_name[1] + '\n')
         #### name_firstname with uppercase
         output.write(list_name[1] + "_" + list_name[0] + '\n')
         #### F.name with uppercase
         output.write(list_name[0][0] + "." + list_name[1] + '\n')
         #### N.firstname with uppercase
         output.write(list_name[1][0] + "." + list_name[0] + '\n')
         #### name.F with uppercase
         output.write(list_name[1] + "." + list_name[0][0] + '\n')
         #### firstname.N with uppercase
         output.write(list_name[0] + "." + list_name[1][0] + '\n')
         #### F-name with uppercase
         output.write(list_name[0][0] + "-" + list_name[1] + '\n')
         #### N-firstname with uppercase
         output.write(list_name[1][0] + "-" + list_name[0] + '\n')
         #### name-F with uppercase
         output.write(list_name[1] + "-" + list_name[0][0] + '\n')
         #### firstname-N with uppercase
         output.write(list_name[0] + "-" + list_name[1][0] + '\n')
         #### Fname with uppercase
         output.write(list_name[0][0] + list_name[1] + '\n')
         #### Nfirstname with uppercase
         output.write(list_name[1][0] + list_name[0] + '\n')
         #### nameF with uppercase
         output.write(list_name[1] + list_name[0][0] + '\n')
         #### firstnameN with uppercase
         output.write(list_name[0] + list_name[1][0] + '\n')
         #### F_name with uppercase
         output.write(list_name[0][0] + "_" + list_name[1] + '\n')
         #### N_firstname with uppercase
         output.write(list_name[1][0] + "_" + list_name[0] + '\n')
         #### name_F with uppercase
         output.write(list_name[1] + "_" + list_name[0][0] + '\n')
         #### firstname_N with uppercase
         output.write(list_name[0] + "_" + list_name[1][0] + '\n')

         line = fp.readline().lower()
         nb_user+=52
print("Usernames written to output file " + output_file +"\nNumber of users created: " + str(nb_user) + "\n------------------------------------------------------")
