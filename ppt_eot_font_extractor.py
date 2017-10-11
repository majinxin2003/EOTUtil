'''
    Description: A hacky script to extract EOT embedded in PowerPoint document (CFBF)
    Author: @x9090
'''

import re
import os
import struct
import olefile
import tempfile
import argparse
import logging

logger = logging.getLogger(__file__)

def setup_logger():
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Setup StreamHandler
    streamhandler = logging.StreamHandler()
    streamhandler.setFormatter(formatter)
    logger.addHandler(streamhandler)
    # Setup FileHandler
    fd, logfilename = tempfile.mkstemp()
    fh = logging.FileHandler(logfilename)
    logger.addHandler(fh)

def extract_eot_by_filename(filepath):
    ole = olefile.OleFileIO(filepath)
    
    '''
    struct _EOT{
        0x00 ULONG   EOTSize;
        0x04 ULONG   FontDataSize;
        0x08 ULONG   Version
        0x0C ULONG   Flags
        0x10 CHAR    FontPANOSE[10];
        0x1B CHAR    Italic;
        0x1C ULONG   Weight;
        0x20 USHORT  fsType;
        0x22 USHORT  MagicNumber;    // 0x504C
        0x24 ULONG   UnicodeRange1;
        0x28 ULONG   UnicodeRange2;
        0x2C ULONG   UnicodeRange3
        0x30 ULONG   UnicodeRange4;
        0x34 ULONG   CodePageRange1;
        0x38 ULONG   CodePageRange2;
        0x3C ULONG   CheckSumAdjustment;
        0x40 ULONG   Reserved1;
        0x44 ULONG   Reserved2;
        0x48 ULONG   Reserved3;
        0x4C ULONG   Reserved4;
        0x50 USHORT  Padding1;
        0x52 USHORT  FamilyNameSize;
        0x54 CHAR    FamilyName[FamilyNameSize];
        ...
    }EOT;
    '''
    OFFSET_TO_EOT_HEADER_FROM_MAGIC = 0x22
    index = 0
    for entry in ole.listdir():
        # EOT typically stored in one of the entries
        if entry[0] in ["PowerPoint Document"]:
            size = ole.get_size(entry)
            # Bail out if size is less than 10KB
            if size > 10000:
                buffer = ole.openstream(entry).read(size)
                for m in re.finditer(r"\x00\x4C\x50", buffer):
                    startoff_eot = m.start()-OFFSET_TO_EOT_HEADER_FROM_MAGIC+1
                    eot = struct.unpack("<LLLL", buffer[startoff_eot:startoff_eot+16])
                    Version = eot[2]
                    # Only the following available EOT version is supported
                    if Version == 0x00010000 or Version == 0x00020001 or Version == 0x00020002:
                        index += 1
                        EOTSize = eot[0]
                        # Use EOT file's extension
                        dirname = os.path.dirname(filepath)
                        outputeot = os.path.abspath(os.path.join(dirname, os.path.basename(filepath).split('.')[0] + "_{0}.eot".format(index)))
                        logger.info("Found EOT. Extracting EOT %d as %s" % (index, outputeot))
                        with open(outputeot, "wb") as fout:
                            fout.write(buffer[startoff_eot:startoff_eot+EOTSize])
                            fout.close()
    
    if index == 0:
        logger.info('Done. No EOT found in %s' % filepath)
    else:
        logger.info('Done. Total number of EOT found in \"%s\": %d' % (filepath, index))
        
    ole.close()
    
def start_eot_extractor(args):
    filepath = ""
    if os.path.isdir(args.filepath):
        logger.info('Extracting EOT from files in folder: ' + args.filepath)
        for dirpath, dirnames, files in os.walk(args.filepath):
            for file in files:
                # when the scripts runs on posix environment
                if os.name == "nt":
                    filepath = os.path.abspath(os.path.join(dirpath, file))
                elif os.name == "posix":
                    filepath = os.path.join(dirpath, file)
                else:
                    filepath = os.path.abspath(os.path.join(dirpath, file))
                    
                # Sanity check if the parser.filepath exists
                if not os.path.exists(filepath):
                    raise

                if not olefile.isOleFile(filepath):
                    logger.error('Not OLE file')
                else: 
                    logger.info('Extracting EOT from file: ' + args.filepath)
                    extract_eot_by_filename(filepath)
                    
    elif os.path.isfile(args.filepath):
        logger.info('Extracting EOT from file: ' + args.filepath)
        filepath = args.filepath
        # Sanity check if the parser.filepath exists
        if not os.path.exists(filepath):
            raise

        if not olefile.isOleFile(filepath):
            logger.error('Not OLE file')
            raise
        else:  
            extract_eot_by_filename(filepath)
    else:
        logger.info('Not valid file')
    
    
if __name__ == '__main__':
    logger.info("Powerpoint Embedded OpenType Font Extractor")
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--filepath", help="File name or file path to PowerPoint file to be parsed", action="store", required=True)
    args = parser.parse_args()
    setup_logger()
    start_eot_extractor(args)