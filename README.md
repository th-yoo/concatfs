FUSE: Filesystem in Userspace for easy file concatenation of big files

Files with the string "-concat-" anywhere in the filename are considered
concatenation description special files.

They contain a file list, which, when mounted as a fuse file system
will turn these files into concatenations of the contents of the
contained files.

Gzip-compressed files (.gz) are automatically detected and decompressed
transparently during reads. This allows mixing compressed and uncompressed
files in the same concatenation.

e.g.

```
  file1.MTS
  file2.MTS
  file3.MTS

  bigmovie-concat-file.MTS
```

contents of bigmovie-concat-file.MTS:

```
file1.MTS
file2.MTS
file3.MTS
```

on seperate lines. Empty lines or lines, which do not resolve to a file where
a stat call succeeds, are ignored.

Gzip files are detected by magic bytes (0x1f 0x8b), not by extension:

```
file1.bin
file2.bin.gz
file3.bin
```

The above will transparently decompress file2.bin.gz while reading.

Dependencies
------------

You will need to install libfuse-dev and zlib to compile:

```
sudo apt-get install libfuse-dev zlib1g-dev
```

Building
--------

Using make:

```
make
```

Or manually:

```
gcc -Wall src/concatfs.c `pkg-config fuse --cflags --libs` -lz -o concatfs
```

Usage
-----

```
concatfs path-to-source-dir path-to-target-dir [fuse-mount options]
```

Limitations
-----------

Gzip decompression is sequential-only. Seeking backward within a compressed
chunk requires re-reading from the beginning. This is acceptable for streaming
use cases but may be slow for random access patterns.

The uncompressed size reported for gzip files is read from the gzip trailer,
which stores size modulo 2^32. Files larger than 4GB uncompressed will report
incorrect sizes.
