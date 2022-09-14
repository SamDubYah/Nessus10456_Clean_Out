import re 
import os
import csv
import tkinter as tk 
from tkinter import filedialog

# Author: Samuel Warner
# Date: 01/13/22

##### CHANGELOG #####
# Name - Date: Changes made
# Swarner - 09/14/2022: Updated to include dns fields
#####################

# How to use:
# 1. Search Plugin ID 10456 in SC under Vulnerabilities (Apply additional filters as needed)
# 2. Select View 'Vulnerability Details'
# 3. Export to CSV 
#   a. Only required fields are IP Address, DNS and Plugin Text (All other fields should get dropped
# 4. Run this scripts
# 5. Select file exported from step 3
# 6. New file created named 'Services_Converted.csv' is created with appropiate info



def active_dict_builder(host, ip_addr, active_list, inactive_list):
    return {"host": host, "ip_addr": ip_addr, "active": active_list, "inactive": inactive_list}


def get_active_inactive(plugin_output):
    regActive = r'Active Services :\n\n(.*)\n\nInactive Services :(?s)' #Find everything between 'Active Services :\n\n' and 'Inactive Services :' (?s) allows matching . to all characters including new lines
    regInactive = r'Inactive Services :\n\n(.*)$(?s)'#Find from 'Inactive Services :' to end of item (?s) allows matching . to all characters including new lines
        
    active_list = re.search(regActive,plugin_output).group(1).strip().split('\n')#Builds list of active items, stripping new line characters
    inactive_list = re.search(regInactive,plugin_output).group(1).strip().split('\n') #Builds list of inactive items, stripping new line characters
        
    return active_list, inactive_list
    
def write_to_disk(complete_list,fobject):
    # Writes the contents of the provided list to a file
    fields = ['Host', 'IP Address', 'Active Services', 'Inactive Services']
    writer = csv.DictWriter(fobject, fieldnames=fields)

    writer.writeheader()
    for i in complete_list:
        writer.writerow({'Host': i['host'], 'IP Address': i['ip_addr'], 'Active Services':"\n".join(i['active']), 'Inactive Services':"\n".join(i['inactive'])}) #"\n".join() convers ',' to '\n'

    return

def csv_list_builder(fobject):
    csv_built_list = []
    
    #print(fobject)
    for row in csv.DictReader(fobject):
        host = row['DNS Name']
        ip_addr = row['IP Address']
        active_list, inactive_list = get_active_inactive(row['Plugin Text'])
        
        csv_built_list.append(active_dict_builder(host, ip_addr, active_list, inactive_list))

    return csv_built_list

def main():
    root = tk.Tk()
    root.withdraw()
    csv_path = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select Plugin Output CSV", filetypes=[("CSV Files", "*.csv")])
    
    #Try to open both files for reading & writing, if fail print exception and exit.
    # services_converted.csv gets written to the same folder as the plugin_output.csv
    try:
        with open(csv_path, "r") as fread, open(os.path.dirname(csv_path)+'/services_converted.csv','w', newline='') as fwrite:
            split_list = csv_list_builder(fread)
            write_to_disk(split_list,fwrite)
    except Exception as e:
        print(e,'\n\n')
        os.system('pause')
    
    
if __name__ == "__main__":
    main()
    
v
