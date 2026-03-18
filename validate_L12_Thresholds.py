
import os
import subprocess
import collections
import logging
import re

import numpy as np

from ctypes import *

THIS_FOLDER = os.path.abspath(os.path.dirname(__file__))
LOCAL_TMP_FILE = os.path.join(THIS_FOLDER, '__tmp.bin')
ProcessOutput = collections.namedtuple("ProcessOutput", ["Output", "ReturnCode"])

logger = logging.getLogger(__name__)

###### START rwe_parser.py methods #########

PCI_DEVICE_LINE_REGEX = r'Bus (\w*), Device (\w*), Function (\w*) \- (.*)'
RWE_ADDRESS_REGEX = r' Address=(\w*?), '
PCILocation = collections.namedtuple("PCILocation", ['Bus', 'Device', 'Function'])

def getBinaryFromHexDump(hexDumpStr):
    '''
    Brief:
        Gets a binary representation of the string hex dump RWE would print in some cases
    '''
    lines = hexDumpStr.splitlines()
    lines = [line for line in lines if line[0] != ' '] # remove spaced lines
    lines = [line for line in lines if line[1] != 'u'] # remove dump lines
    lines = [line for line in lines if line[2] != 'r'] # remove parameter error lines
    ret = []
    for line in lines:
        line = line.split(' ', 1)[1] # remove index
        line = line.split('\t')[0]   # remove ascii
        ret += [int(c, 16) for c in line.split()]

    return bytearray(ret)

def bytesToDWordList(b):
    '''
    Brief:
        Convert a list of bytes to a list of DWords
    '''
    ret = []
    for idx in range(0, len(b), 4):
        d = b[idx] + (b[idx + 1] << 8) + (b[idx + 2] << 16) + (b[idx + 3] << 24)
        ret.append(d)

    return ret

def pciTreeTextToDict(txt):
    '''
    Brief:
        Converts a PCI tree's text to a dict of PCI devices to descriptions
    '''
    a = re.findall(PCI_DEVICE_LINE_REGEX, txt)
    retDict = {}
    for itm in a:
        retDict[
            PCILocation(int(itm[0], 16), int(itm[1], 16), int(itm[2], 16))
        ] = itm[3].strip()

    return retDict

def verifyAddress(address, rweOutput):
    '''
    Brief:
        Verifies that the given address matches the RWE output. Raises if it is mismatched.
            Note that there are some current issues with 64-bit addresses and RWE not handling them properly in commands.
                This should at least tell the user if that happens, though there is no current workaround.
                    I've emailed RWE's Jeff about this bug. Said it should be fixed in a future release.
    '''
    #print(f'{address} ||| {rweOutput}')
    m = re.findall(RWE_ADDRESS_REGEX, rweOutput)
    rweAddr = int(m[0], 16)
    if address != rweAddr:
        raise RuntimeError("RWE Didn't process the correct address! It processed: 0x%X instead of 0x%X" % (rweAddr, address))

###### END rwe_parser.py methods #########



###### START finder.py methods #########

BIN_FOLDER = os.path.join(THIS_FOLDER, 'bin')
X86_BIN_FOLDER = os.path.join(BIN_FOLDER, 'x86')
X64_BIN_FOLDER = os.path.join(BIN_FOLDER, 'x64')

X64_PROGRAM_FILES = '/Program Files (x86)'

RW_EXE = 'Rw.exe'
DEFAULT_INSTALL_LOCATIONS = [
    "/Program Files/RW-Everything/%s" % RW_EXE,
    "/Program Files (x86)/RW-Everything/%s" % RW_EXE,
]

def findInstalledRWEverything():
    '''
    Brief:
        Searches for an installed version of RW-Everything. If found, returns the string path.
    '''
    drivePath = os.environ.get('SYSTEMDRIVE', 'C:')
    for defInstLoc in DEFAULT_INSTALL_LOCATIONS:
        fullPath = os.path.join(drivePath, defInstLoc)
        if os.path.isfile(fullPath):
            try:
                ReadWriteEverything(fullPath)
                return fullPath
            except EnvironmentError:
                continue

def getEnvironmentVariableAsList(v):
    '''
    Brief:
        Returns the given environment variable's values as a list
    '''
    return os.environ.get(v, '').split(os.pathsep)

def findPathedRWEverything():
    '''
    Brief:
        Searched for a RW-Everything executable in the system path. If found, returns the string path.
    '''
    path = getEnvironmentVariableAsList('PATH')
    for p in path:
        possibleRw = os.path.join(p, RW_EXE)
        if os.path.isfile(possibleRw):
            try:
                ReadWriteEverything(possibleRw)
                return possibleRw
            except EnvironmentError:
                continue

def findCwdRWEverything():
    '''
    Brief:
        Searches the current working directory for RWE
    '''
    fullPath = os.path.join(os.getcwd(), RW_EXE)
    if os.path.isfile(fullPath):
        try:
            ReadWriteEverything(fullPath)
            return fullPath
        except EnvironmentError:
            pass

def findPackagedRWEverything():
    '''
    Brief:
        Finds the RWE packaged with this module
    '''
    folder = X86_BIN_FOLDER
    if os.environ.get('ProgramFiles(x86)', False):
        # 64 bit
        folder = X64_BIN_FOLDER

    loc = os.path.join(folder, RW_EXE)
    if os.path.isfile(loc):
        return loc

def findRWEverything():
    '''
    Brief:
        Searches known directories for RWE
    '''
    r = findCwdRWEverything()
    if r:
        return r
    
    r = findPathedRWEverything()
    if r:
        return r

    r = findPackagedRWEverything()
    if r:
        return r

    r = findInstalledRWEverything()

    return r

###### END finder.py methods #########


class ReadWriteEverything(object):
    '''
    Derrived from https://github.com/csm10495/PyRW/
    
    Brief:
        Easy to use abstractions for RWE in Python
    '''
    
    def __init__(self, exePath=None):
        '''
        Brief:
            Initializer for the class. Takes the path to rw.exe
                Ensures we have admin and that rw.exe seems to work
        '''

        if exePath is None:
            exePath = findRWEverything()

        self.exePath = exePath
        self.version = self.getRWEVersion()

        if not windll.shell32.IsUserAnAdmin():
            raise EnvironmentError("Please run as admin")

        self._checkValidRWExe()
    
    def _checkValidRWExe(self):
        '''
        Brief:
            Does a stupidly silly check to see if rw.exe appears to work
        '''
        r = self.callRWECommand("COUT Hello World;rwexit")
        if 'RW Exit' in r.Output and 'Hello World' in r.Output and r.ReturnCode:
            raise EnvironmentError("%s does not appear to be a valid RW-Everything exe" % self.exePath)
    
    def getRWEVersion(self):
        '''
        Brief:
            Uses some magic to get the RWE version
        '''
        if hasattr(self, 'version'):
            return self.version

        version = subprocess.check_output('powershell "(Get-Item -path \\"%s\\").VersionInfo.FileVersion"' % self.exePath).strip().decode()
        with open(self.exePath, 'rb') as f:
            # https://superuser.com/questions/358434/how-to-check-if-a-binary-is-32-or-64-bit-on-windows
            f.seek(0x204)
            if f.read(1)[0] == 0x64:
                b = 'x64'
            else:
                b = 'x86'

        v = 'RW - Read Write Utility v%s %s' % (version, b)
        self.version = v
        logger.debug("RWE Version: %s" % v)
        return self.version
    
    def callRawCommand(self, cmd):
        '''
        Brief:
            Calls a Raw command on rw.exe
        '''
        fullCmd = '\"%s\" %s' % (self.exePath, cmd)
        logger.debug("Calling raw command: %s" % fullCmd)
        try:
            output = subprocess.check_output(fullCmd, shell=True, stderr=subprocess.STDOUT)
            retCode = 0
        except subprocess.CalledProcessError as ex:
            output = ex.output
            retCode = ex.returncode

        ret = ProcessOutput(Output=output.decode(), ReturnCode=retCode)
        logger.debug("... Returned: %s" % str(ret))
        return ret

    def callRWECommand(self, cmd):
        '''
        Brief:
            Calls an embeded RWE command on rw.exe
        '''
        fullCommand = '/Min /Nologo /Stdout /Command="%s"' % (cmd.replace('\"', '\\"'))
        return self.callRawCommand(fullCommand)
        
    def readMemory(self, byteOffset, numBytes):
        '''
        Brief:
            Reads raw memory from a given offset for a given number of bytes
        '''
        cmd = "SAVE \"%s\" Memory 0x%X %d" % (LOCAL_TMP_FILE, byteOffset, numBytes);
        print(f"Execute SAVE command: {cmd}");
        n = self.callRWECommand(cmd)
        assert n.ReturnCode == 0, "Didn't return 0"
        verifyAddress(byteOffset, n.Output)

        with open(LOCAL_TMP_FILE, 'rb') as f:
            data = f.read()
        #os.remove(LOCAL_TMP_FILE)
        return data
        

def pci_dev(bus, device, func):
    return {'bus': bus, 'device': device, 'func': func};

def to_pcie_register_1(mcfg_base, bus, dev, func, offset):
    return mcfg_base + (bus << 20) + (dev << 15) + (func << 12) + offset;

def to_pcie_register(mcfg_base, dev, offset):
    return to_pcie_register_1(mcfg_base, dev['bus'], dev['device'], dev['func'], offset);

def find_in_cap_list(name, mcfg_base, device, bytes):
    int32_array_np = np.frombuffer(bytes, dtype=np.uint32);
    int32_list = int32_array_np.tolist();
    #print(f"{int32_list}");
    
    cur = int32_list[0];
    
    found_threshold = False;
    
    print(f"{name}: Scanning PCIe capabilities for L1.2 Threshold with ID 0x001E...");
    
    iter = 0;
    while True:
        cap_ID = cur & 0x0000FFFF;
        next_val = (cur & 0xFFF00000) >> 20;
        next = int( (to_pcie_register(mcfg_base, device, next_val) - to_pcie_register(mcfg_base, device, 0x100)) / 4 );
        #next = int( (next_val - 0x100) / 4 );
        
        print(f"\t{name}: 0x{cur:X}: Capability ID: 0x{cap_ID:X}, Next val: {next_val}, Next: {next}");
        
        if (next_val == 0 or iter > 30):
            break;
            
        if (cap_ID == 0x001E):
            val = int32_list[next];
            LTRL12TV = (val & 0x03FF0000) >> 16;
            scale = (val & 0xE0000000) >> 29;
            print(f"\t{name}: Found capability 0x001E at {to_pcie_register(mcfg_base, device, next_val):X}: 0x{val:X} -> {LTRL12TV} at 0b{scale:03b}");
            found_threshold = True;
            break;
        
        cur = int32_list[next];
        iter += 1;
    
    if not found_threshold:
        print(f"\t{name}: Failed to find capability 0x001E");

def check_L12():
    
    pcie_root = pci_dev(0, 1, 0);
    gpu_pcie = pci_dev(1, 0, 0);
    
    rwe = ReadWriteEverything()
    print(f"Found {rwe.version} at {rwe.exePath}");
    
    MCFG_table_lines = rwe.callRWECommand("ACPI Dump MCFG").Output.split('\r\n');
    rwe.callRWECommand("rwexit");
    
    base_addr_str = "0x00000000C0000000"; # default most likely
    found = False;
    for l in MCFG_table_lines:
        if ("  Base Address" in l and "0x" in l):
            base_addr_str = f"0x{l.split('0x')[1]}";
            found = True;
    
    if (found):
        print(f"MCFG Base Address found: {base_addr_str}");
    else:
        print(f"MCFG Base Address NOT found... using default {base_addr_str}");
    
    mcfg_base_addr = int(base_addr_str, 0)
    
    pcie_root_reg_start = to_pcie_register(mcfg_base_addr, pcie_root, 0x100);
    gpu_pcie_reg_start = to_pcie_register(mcfg_base_addr, gpu_pcie, 0x100);
    
    print(f"PCIe root register address: 0x{pcie_root_reg_start:X}");
    print(f"PCIe GPU register address: 0x{gpu_pcie_reg_start:X}");
    
    pcie_root_reg_cap_bytes = rwe.readMemory(pcie_root_reg_start, 0xFFF - 0x100 + 1);
    pcie_gpu_reg_cap_bytes = rwe.readMemory(gpu_pcie_reg_start, 0xFFF - 0x100 + 1);
    
    find_in_cap_list("PCIe Root Config", mcfg_base_addr, pcie_root, pcie_root_reg_cap_bytes);
    find_in_cap_list("GPU PCIe Config", mcfg_base_addr, gpu_pcie, pcie_gpu_reg_cap_bytes);
    
    
    
    
if __name__ == '__main__':
    check_L12();