import argparse
import collections
import contextlib
import hashlib
import mmap
import os.path
import struct
import sys

# Named tuple for unpacking the SQLite header
SQLite_header = collections.namedtuple('SQLite_header', (
    'magic',
    'page_size',
    'write_format',
    'read_format',
    'reserved_length',
    'max_payload_fraction',
    'min_payload_fraction',
    'leaf_payload_fraction',
    'file_change_counter',
    'size_in_pages',
    'first_freelist_trunk',
    'freelist_pages',
    'schema_cookie',
    'schema_format',
    'default_page_cache_size',
    'largest_btree_page',
    'text_encoding',
    'user_version',
    'incremental_vacuum',
    'application_id',
    'version_valid',
    'sqlite_version',
))

# Named tuple for yielding the matching results
Match = collections.namedtuple('Match', ['start_offset', 'end_offset'])

def carve_sqlite(mm):
    """
    :param mm: Memorymap of binary data
    :yields: Matches for sqlite files
    """
    # Start at the beginning of the file of course
    offset = 0

    while True:
        # Search for the magic bytes of SQLite3
        offset = mm.find(b'\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00', offset)
        if offset == -1:
            break
        else:
            # We have found a possible SQLite database

            # This DB header is always big-endian
            fields = SQLite_header(*struct.unpack(
                r'>16sHBBBBBBIIIIIIIIIIII20xII',
                mm[offset:offset + 100]
            ))

            # Calculate the end-offset of the SQLite database by using the header information
            db_size = fields.page_size * fields.size_in_pages

            # Yield it for later usage
            yield Match(offset, db_size + offset)

        offset += 1


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Extract SQLite files from binary dump.")
    parser.add_argument("binary", type=str, help="Path to input binary dump")

    args = parser.parse_args()

    print("Stared carving... This may take a while...\n")
    with open(args.binary, "rb") as f:
        # Create a memorymap file of the binary for efficient searching
        with contextlib.closing(mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ)) as m:
            for match in carve_sqlite(m):
                md5_hash = hashlib.md5()
                md5_hash.update(m[match.start_offset:match.end_offset])
                print("Found SQLite magic bytes:",
                      "\n\tStart-Offset: " + str(match.start_offset),
                      "\n\tEnd-Offset: " + str(match.end_offset),
                      "\n\tMD5-Hash: " + md5_hash.hexdigest())

                # If identical file not already extracted, write it to output
                filepath = os.path.join("output", md5_hash.hexdigest() + ".sqlite")
                if not os.path.isfile(filepath):
                    print("Writing match to", filepath, "\n")
                    with open(os.path.join("output", md5_hash.hexdigest() + ".sqlite"), 'wb') as g:
                        g.write(m[match.start_offset:match.end_offset])
                else:
                    print("Not writing file, because", filepath, "already exists.\n")



if __name__ == "__main__":
    sys.exit(main())