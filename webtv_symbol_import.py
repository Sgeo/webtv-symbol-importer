"""
    IDA Symbol Importer for WebTV (MSNTV) Builds

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version
    3 of the License, or (at your option) any later version.

    Author: Eric MacDonald <ubergeek03@gmail.com>
    Date: January 30th, 2015
"""

from idaapi import * 
import idautils
import idc

chunk_size = 4096

class WTV_SYMBOLS_LOADER:

    # Show a prompt to the user allowing them to select the symbol file.
    def __init__(self):
        file_name = AskFile(0, "*.sym", "WebTV Build Symbol File")

        if file_name != "":
            symbols = self.read_symbols(file_name)

            self.import_symbols(symbols)
        else:
            Message("No symbol file selected. Exiting\n")

    # Reads the entire symbol file into memory.
    def read_symbol_file(self, file_name, chunk_size=chunk_size):
        Message("Reading '" + file_name + "'\n")

        symbol_file_contents = "";

        with open(file_name, "rb") as FILE:
            while True:
                chunk = FILE.read(chunk_size)

                if chunk:
                    symbol_file_contents += chunk;
                else:
                    break

        Message("Read " + str(len(symbol_file_contents)) + " bytes.\n")

        return symbol_file_contents
    
    # Process the read symbol file and return the list of names.
    def read_symbols(self, file_name, chunk_size=chunk_size):
        symbols = {}

        symbol_file_contents = self.read_symbol_file(file_name, chunk_size)
        symbol_file_version = 0
        class_names = []

        read_length = 0
        file_length = len(symbol_file_contents)

        Message("Parsing symbol file.\n")

        # The symbol file format can be found by checking the first 4 bytes of
        # the file (magic)
        version_check = struct.unpack_from(">I", 
            symbol_file_contents, read_length)[0]

        # This seems to be the first symbol file format used.
        # It starts with with a memory address (0x80XXXXXX)
        if (version_check & 0xFF000000) == 0x80000000:
            symbol_file_version = 0
        # This is the most common symbol file format and seems to be what
        # Microsoft settled on.
        # Classes are named at the bottom of the file.
        elif version_check == 1:
            symbol_file_version = 1

            class_start_index = symbol_file_contents.rfind("\x00")

            if class_start_index > -1:
                Message("Class name list at offset %x" % 
                    class_start_index + "\n")

                # Class names are a newline terminated list at the bottom of the
                # file.
                class_names = \
                   symbol_file_contents[class_start_index:].split("\x0A")

                file_length = class_start_index

                Message("Reducing symbol file length to " + 
                    str(file_length) + " bytes.\n")

            read_length = 12
        # Odd format that isn't used much.  These files start with "TIMN"
        # Probably named after "Tim Nicholas" who worked on parts of the WebTV
        # debugger.
        elif version_check == 0x54494D4E:
            symbol_file_version = 2
            read_length = 8

        Message("Reading symbols for symbol file of version '" +
            str(symbol_file_version) + "'.\n")

        while(read_length < file_length):
            object_address = 0
            object_name = ""

            # The memory address is always a 4-byte little-endian unsigned
            # integer.
            object_address = struct.unpack_from(">I", 
                symbol_file_contents, read_length)[0]

            read_length += 4

            # This is the part that is different between all symbol file
            # formats.  So we read the first byte to make sure we know what's 
            # next.
            object_name_check = struct.unpack_from(">B", 
                symbol_file_contents, read_length)[0]

            # If we see a 0x80 then this is a class index with a null-terminated
            # method or property. The index is used to lookup a class name based
            # on the order of names at the bottom of the file.
            if object_name_check == 0x80:
                read_length += 1

                class_name_index = struct.unpack_from(">H",
                    symbol_file_contents, read_length)[0]

                read_length += 2

                string_length = \
                   (symbol_file_contents[read_length:]).find("\x00")

                object_name = symbol_file_contents[
                    read_length:(read_length + string_length)]
                
                read_length += string_length + 1

                if class_name_index < len(class_names):
                    object_name = \
                       class_names[class_name_index] + "::" + object_name;
            
            # The "TIMN" symbol file has the string length in front of the
            # object-name string.
            elif symbol_file_version == 2:
                read_length += 1

                string_length = object_name_check

                object_name = symbol_file_contents[
                    read_length:(read_length + string_length)]

                read_length += string_length
            # Otherwise we read a null-terminated object-name string.
            else:
                string_length = \
                   (symbol_file_contents[read_length:]).find("\x00")

                object_name = symbol_file_contents[
                    read_length:(read_length + string_length)]

                read_length += string_length + 1

            symbols[object_address] = object_name
        
        Message("Read '" + str(len(symbols)) + "' symbols.\n")

        return symbols

    # Assign names to addresses based on a symbol list.
    def import_symbols(self, symbols):
        Message("Importing symbols into IDA.\n")

        for object_address in symbols.keys():
            MakeNameEx(object_address, symbols[object_address], SN_NOWARN)

        Message("Done importing.\n")


Message("START: Eric's symbol file loader.\n")

WTV_SYMBOLS_LOADER()
