import argparse
import sys
from struct import *

fileName = ''
fileClassID = ''

fileTypes = {0:'No file type', 1:'Relocatable object file', 2:'Executable file', 3:'Shared object file', 4:'Core file'}
machines = {3:'Intel 80386', 62:'AMD x86-64 architecture'}
versions = {0:'Invalid version', 1:'Current version'}
datas = {1:'Little-endian', 2:'Big-endian'}
classes = {1:'32-bit objects', 2:'64-bit objects'}

sectionTypes = {0:'SHT_NULL', 1:'SHT_PROGBITS', 2:'SHT_SYMTAB', 3:'SHT_STRTAB', 4:'SHT_RELA', 5:'SHT_HASH', 6:'SHT_DYNAMIC', 7:'SHT_NOTE', 8:'SHT_NOBITS', 9:'SHT_REL', 10:'SHT_SHLIB', 11:'SHT_DYNSYM', 14:'SHT_INIT_ARRAY', 15:'SHT_FINI_ARRAY', 16:'SHT_PREINIT_ARRAY', 17:'SHT_GROUP', 18:'SHT_SYMTAB_SHNDX', 19:'SHT_NUM'}
sectionFlags = {0:'', 1:'SHF_WRITE', 2:'SHF_ALLOC', 3:'SHF_EXECINSTR'}

symbolBinding = {0:'LOCAL', 1:'GLOBAL', 2:'WEAK', 10:'LOOS', 12:'HIOS', 13:'LOPROC', 15:'HIPROC'}
symbolTypes = {0:'NOTYPE', 1:'OBJECT', 2:'FUNC', 3:'SECTION', 4:'FILE', 10:'LOOS', 12:'HIOS', 13:'LOPROC', 15:'HIPROC'}

symbolFlag = {0:'Static', 1:'Dynamic'}
class elfHeaderClass:

    def __init__(self):
        self.e_indent = []
        self.e_type = ''
        self.e_machine = ''
        self.e_version = ''
        self.e_entry = ''
        self.e_phoff = ''
        self.e_shoff = ''
        self.e_flags = ''
        self.e_ehsize = ''
        self.e_phentsize = ''
        self.e_phnum = ''
        self.e_shentsize = ''
        self.e_shnum = ''
        self.e_shstrndx = ''

class sectionHeaderClass:

    def __init__(self):
        self.sh_name = ''
        self.sh_type = ''
        self.sh_flags = ''
        self.sh_addr = ''
        self.sh_offset = ''
        self.sh_size = ''
        self.sh_link = ''
        self.sh_info = ''
        self.sh_addralign = ''
        self.sh_entsize = ''

    def getName(self):
        return self.sh_name
    def setName(self, name):
        self.sh_name = name

class symbolTableClass:

    def __init__(self):
        self.st_name = ''
        self.st_info = ['', '']
        self.st_other = ''
        self.st_shndx = ''
        self.st_value = ''
        self.st_size = ''

    def getName(self):
        return self.st_name
    def setName(self, name):
        self.st_name = name

curElfHeader = elfHeaderClass()
curSectionHeader = []
curStaticSymbolTable = []
curDynamicSymbolTable = []

def elfHeaderParser():
    global curElfHeader
    global fileClassID
    offset = 0
    decimalValue = 0

    file = open(fileName, 'rb')

    for i in range(16):
        chunk = file.read(1)
        offset += 1
        curElfHeader.e_indent.append(chunk.encode('hex'))

    if not magicalCheck():
        file.close()
        exit()

    fileClassID = int(curElfHeader.e_indent[4], 16)

    chunk = file.read(2)
    offset += 2
    decimalValue = unpack('H', chunk)[0]
    curElfHeader.e_type = fileTypes[decimalValue]

    chunk = file.read(2)
    offset += 2
    decimalValue = unpack('H', chunk)[0]
    curElfHeader.e_machine = machines[decimalValue]

    chunk = file.read(4)
    offset += 4
    decimalValue = unpack('I', chunk)[0]
    curElfHeader.e_version = versions[decimalValue]
    if fileClassID == 1:
        for i in range(4):
            chunk = file.read(1)
            offset += 1
            curElfHeader.e_entry = chunk.encode('hex') + curElfHeader.e_entry

        curElfHeader.e_entry = '0x' + curElfHeader.e_entry

        for i in range(4):
            chunk = file.read(1)
            offset += 1
            curElfHeader.e_phoff = chunk.encode('hex') + curElfHeader.e_phoff

        curElfHeader.e_phoff = '0x' + curElfHeader.e_phoff

        for i in range(4):
            chunk = file.read(1)
            offset += 1
            curElfHeader.e_shoff = chunk.encode('hex') + curElfHeader.e_shoff

        curElfHeader.e_shoff = '0x' + curElfHeader.e_shoff
    else:
        for i in range(8):
            chunk = file.read(1)
            offset += 1
            curElfHeader.e_entry = chunk.encode('hex') + curElfHeader.e_entry

        curElfHeader.e_entry = '0x' + curElfHeader.e_entry

        for i in range(8):
            chunk = file.read(1)
            offset += 1
            curElfHeader.e_phoff = chunk.encode('hex') + curElfHeader.e_phoff

        curElfHeader.e_phoff = '0x' + curElfHeader.e_phoff

        for i in range(8):
            chunk = file.read(1)
            offset += 1
            curElfHeader.e_shoff = chunk.encode('hex') + curElfHeader.e_shoff

        curElfHeader.e_shoff = '0x' + curElfHeader.e_shoff

    chunk = file.read(4)
    offset += 4
    decimalValue = unpack('I', chunk)[0]
    curElfHeader.e_flags = decimalValue

    chunk = file.read(2)
    offset += 2
    decimalValue = unpack('H', chunk)[0]
    curElfHeader.e_ehsize = decimalValue

    chunk = file.read(2)
    offset += 2
    decimalValue = unpack('H', chunk)[0]
    curElfHeader.e_phentsize = decimalValue

    chunk = file.read(2)
    offset += 2
    decimalValue = unpack('H', chunk)[0]
    curElfHeader.e_phnum = decimalValue

    chunk = file.read(2)
    offset += 2
    decimalValue = unpack('H', chunk)[0]
    curElfHeader.e_shentsize = decimalValue

    chunk = file.read(2)
    offset += 2
    decimalValue = unpack('H', chunk)[0]
    curElfHeader.e_shnum = decimalValue

    chunk = file.read(2)
    offset += 2
    decimalValue = unpack('H', chunk)[0]
    curElfHeader.e_shstrndx = decimalValue

    if offset != curElfHeader.e_ehsize:
        file.close()
        exit()
    file.close()

def magicalCheck():
    check = False
    magicNumber = ''

    for i in range(4):
        magicNumber += curElfHeader.e_indent[i]

    if magicNumber == '7f454c46':
        check = True

    return check

def sectionHeaderParser():
    if not curElfHeader:
        exit()
    
    offset = 0
    chunk = ''
    decimalValue = 0
    headerOffset = int(curElfHeader.e_shoff, 16)

    entryCount = curElfHeader.e_shnum
    entrySize = curElfHeader.e_shentsize
