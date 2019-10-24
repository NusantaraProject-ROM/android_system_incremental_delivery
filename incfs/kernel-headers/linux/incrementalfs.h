/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Userspace interface for Incremental FS.
 *
 * Incremental FS is special-purpose Linux virtual file system that allows
 * execution of a program while its binary and resource files are still being
 * lazily downloaded over the network, USB etc.
 *
 * Copyright 2019 Google LLC
 */
#ifndef _UAPI_LINUX_INCREMENTALFS_H
#define _UAPI_LINUX_INCREMENTALFS_H

#include <linux/ioctl.h>
#include <linux/limits.h>
#include <linux/types.h>

/* ===== constants ===== */
#define INCFS_NAME "incremental-fs"
#define INCFS_MAGIC_NUMBER (0x5346434e49ul)
#define INCFS_DATA_FILE_BLOCK_SIZE 4096
#define INCFS_HEADER_VER 1

#define INCFS_MAX_HASH_SIZE 64

#define INCFS_MAX_FILES 1000
#define INCFS_COMMAND_INODE 1
#define INCFS_LOG_INODE 2
#define INCFS_ROOT_INODE 100
#define INCFS_MAX_FILE_ATTR_SIZE 512

#define INCFS_IOCTL_BASE_CODE 'g'

/* ===== ioctl requests on command file ===== */

/* Make changes to the file system via incfs instructions. */
#define INCFS_IOC_PROCESS_INSTRUCTION _IOWR(INCFS_IOCTL_BASE_CODE, 30, struct incfs_instruction)

/* Read file attribute by inode */
#define INCFS_IOC_READ_FILE_ATTR \
    _IOWR(INCFS_IOCTL_BASE_CODE, 31, struct incfs_get_file_attr_request)

/* Read file blockmap */
#define INCFS_IOC_READ_FILE_BMAP \
    _IOWR(INCFS_IOCTL_BASE_CODE, 32, struct incfs_get_file_bmap_request)

/*
 * Description of a pending read. A pending read - a read call by
 * a userspace program for which the filesystem currently doesn't have data.
 *
 * This structs can be read from .cmd file to obtain a set of reads which
 * are currently pending.
 */

enum incfs_read_kind {
    INCFS_READ_KIND_PENDING,
    INCFS_READ_KIND_SUCCEEDED,
    INCFS_READ_KIND_TIMED_OUT
};

struct incfs_pending_read_info {
    /* Inode number of a file that is being read from. */
    __u32 file_ino;

    /* Index of a file block that is being read. */
    __u32 block_index;

    /* A number of microseconds since system boot to the read. */
    __aligned_u64 timestamp_us;

    /* A serial number of this pending read. */
    __u32 serial_number;

    /* A kind of this read: see enum incfs_read_kind */
    __u32 kind;
};

enum incfs_compression_alg { COMPRESSION_NONE = 0, COMPRESSION_LZ4 = 1 };

enum incfs_block_flags {
    INCFS_BLOCK_FLAGS_NONE = 0,
    INCFS_BLOCK_FLAGS_HASH = 1,
};

/*
 * A struct to be written into a .cmd file to load a data or hash
 * block to a file.
 */
struct incfs_new_data_block {
    /* Inode number of a file this block belongs to. */
    __aligned_u64 file_ino;

    /* Index of a data block. */
    __u32 block_index;

    /* Length of data */
    __u32 data_len;

    /*
     * A pointer ot an actual data for the block.
     *
     * Equivalent to: __u8 *data;
     */
    __aligned_u64 data;

    /*
     * Compression algorithm used to compress the data block.
     * Values from enum incfs_compression_alg.
     */
    __u8 compression;

    /* Values from enum incfs_block_flags */
    __u8 flags;

    __u16 reserved1;

    __u32 reserved2;

    __aligned_u64 reserved3;
};

enum incfs_instruction_type {
    INCFS_INSTRUCTION_NOOP = 0,
    INCFS_INSTRUCTION_NEW_FILE = 1,
    INCFS_INSTRUCTION_ADD_DIR_ENTRY = 3,
    INCFS_INSTRUCTION_REMOVE_DIR_ENTRY = 4
};

enum incfs_hash_tree_algorithm { INCFS_HASH_TREE_NONE = 0, INCFS_HASH_TREE_NONE_SHA256 = 1 };

/*
 * Create a new file or directory.
 * Corresponds to INCFS_INSTRUCTION_NEW_FILE
 */
struct incfs_new_file_instruction {
    /*
     * [Out param. Populated by the kernel after ioctl.]
     * Inode number of a newly created file.
     */
    __aligned_u64 ino_out;

    /*
     * Total size of the new file. Ignored if S_ISDIR(mode).
     */
    __aligned_u64 size;

    /*
     * File mode. Permissions and dir flag.
     */
    __u16 mode;

    __u8 hash_tree_alg; /* Value from incfs_hash_tree_algorithm */

    __u8 reserved1;

    /*
     * Length of the data buffer specfied by file_attr.
     * Max value: INCFS_MAX_FILE_ATTR_SIZE
     */
    __u32 file_attr_len;

    /*
     * A pointer to the file attribute to be set on creation.
     *
     * Equivalent to: u8 *file_attr;
     */
    __aligned_u64 file_attr;

    /*
     * A pointer to file's root hash (if determined != 0)
     * Actual hash size determined by hash_tree_alg.
     * Size of the buffer should be at least INCFS_MAX_HASH_SIZE
     *
     * Equivalent to: u8 *root_hash;
     */
    __aligned_u64 root_hash;

    __aligned_u64 reserved3;

    __aligned_u64 reserved4;

    __aligned_u64 reserved5;
};

/*
 * Create or remove a name (aka hardlink) for a file in a directory.
 * Corresponds to
 * INCFS_INSTRUCTION_ADD_DIR_ENTRY,
 * INCFS_INSTRUCTION_REMOVE_DIR_ENTRY
 */
struct incfs_dir_entry_instruction {
    /* Inode number of a directory to add/remove a file to/from. */
    __aligned_u64 dir_ino;

    /* File to add/remove. */
    __aligned_u64 child_ino;

    /* Length of name field */
    __u32 name_len;

    __u32 reserved1;

    /*
     * A pointer to the name characters of a file to add/remove
     *
     * Equivalent to: char *name;
     */
    __aligned_u64 name;

    __aligned_u64 reserved2;

    __aligned_u64 reserved3;

    __aligned_u64 reserved4;

    __aligned_u64 reserved5;
};

/*
 * An Incremental FS instruction is the way for userspace
 * to
 *   - create files and directories
 *   - show and hide files in the directory structure
 */
struct incfs_instruction {
    /* Populate with INCFS_HEADER_VER */
    __u32 version;

    /*
     * Type - what this instruction actually does.
     * Values from enum incfs_instruction_type.
     */
    __u32 type;

    union {
        struct incfs_new_file_instruction file;
        struct incfs_dir_entry_instruction dir_entry;

        /* Hard limit on the instruction body size in the future. */
        __u8 reserved[64];
    };
};

/*
 * Request a value of a file attribute for a given inode number.
 * Argument for INCFS_IOC_READ_FILE_ATTR ioctl
 */
struct incfs_get_file_attr_request {
    /* Populate with INCFS_HEADER_VER */
    __u32 version;

    __u32 pad1;

    /*
     * Inode number to read an attribute value from.
     */
    __aligned_u64 ino;

    /*
     * A pointer to the data buffer to save an attribute value to.
     *
     * Equivalent to: u8 *file_attr;
     */
    __aligned_u64 file_attr;

    /* Size of the buffer at file_attr. */
    __u32 file_attr_buf_size;

    /* Number of bytes save file_attr buffer. It is set after ioctl done. */
    __u32 file_attr_len_out;

    __aligned_u64 reserved1;

    __aligned_u64 reserved2;
};

/*
 * Request a value of a file block map for a given inode number.
 * Argument for INCFS_IOC_READ_FILE_BMAP ioctl
 */
struct incfs_get_file_bmap_request {
    /* Populate with INCFS_HEADER_VER */
    __u32 version;

    __u32 pad1;

    /*
     * Inode number to read a block map for.
     */
    __aligned_u64 ino;

    /*
     * A pointer to the data buffer to save an block map to.
     *
     * Equivalent to: u8 *file_block_map;
     */
    __aligned_u64 file_block_map;

    /* Size of the buffer at file_block_map. */
    __u32 file_block_map_buf_size;

    /* A total number of blocks loaded to the data file. */
    __u32 blocks_present;

    __aligned_u64 reserved2;

    __aligned_u64 reserved3;
};

#endif /* _UAPI_LINUX_INCREMENTALFS_H */
