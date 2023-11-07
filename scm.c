/**
 * Tony Givargis
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * scm.c
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include "scm.h"

/**
 * Needs:
 *   fstat()
 *   S_ISREG()
 *   open()
 *   close()
 *   sbrk()
 *   mmap()
 *   munmap()
 *   msync()
 */

/* research the above Needed API and design accordingly */

#define HEAP_ADDR 0x600000000000

#define META_HEAP_DATA_SIZE sizeof(size_t)
#define META_BLOCK_BIT_SIZE sizeof(short)
#define META_BLOCK_DATA_SIZE sizeof(size_t)
#define META_BLOCK_SIZE (META_BLOCK_BIT_SIZE + META_BLOCK_DATA_SIZE)

struct scm {
    int fd;
    struct {
        size_t utilized;
        size_t capacity;
    } size;
    void *addr;
};

struct scm *file_size(const char *pathname) {
    struct stat st;
    int fd;
    struct scm *scm;

    assert(pathname);

    if (!(scm = malloc(sizeof(struct scm)))) {
        TRACE("malloc failed");
        return NULL;
    }
    memset(scm, 0, sizeof(struct scm));

    if ((fd = open(pathname, O_RDWR)) == -1) {
        free(scm);
        TRACE("no such file");
        return NULL;
    }

    if (fstat(fd, &st) == -1) {
        free(scm);
        close(fd);
        TRACE("fstat failed");
        return NULL;
    }

    if (!S_ISREG(st.st_mode)) {
        free(scm);
        close(fd);
        TRACE("not a regular file");
        return NULL;
    }

    scm->fd = fd;
    scm->size.utilized = 0;
    scm->size.capacity = st.st_size;

    return scm;
}

struct scm *scm_open(const char *pathname, int truncate) {
    struct scm *scm = file_size(pathname);
    if (!scm) {
        return NULL;
    }

    if (sbrk((long) scm->size.capacity) == (void *) -1) {
        close(scm->fd);
        free(scm);
        TRACE("sbrk failed");
        return NULL;
    }

    if ((scm->addr = mmap((void *) HEAP_ADDR, scm->size.capacity, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED,
                          scm->fd, 0)) == MAP_FAILED) {
        close(scm->fd);
        free(scm);
        TRACE("mmap failed");
        return NULL;
    }

    if (truncate) {
        if (ftruncate(scm->fd, (long) scm->size.capacity) == -1) {
            close(scm->fd);
            free(scm);
            TRACE("ftruncate failed");
            return NULL;
        }
        scm->size.utilized = 0;
    } else {
        scm->size.utilized = *(size_t *) scm->addr;
    }

    return scm;
}

void scm_close(struct scm *scm) {
    assert(scm);

    if (msync(scm->addr, scm->size.capacity, MS_SYNC) == -1) {
        TRACE("msync failed");
    }
    if (munmap(scm->addr, scm->size.capacity) == -1) {
        TRACE("munmap failed");
    }
    if (close(scm->fd) == -1) {
        TRACE("close failed");
    }

    memset(scm, 0, sizeof(struct scm));
    FREE(scm);
}

void *base_addr(struct scm *scm) {
    return (char *) scm->addr + META_HEAP_DATA_SIZE;
}

void set_heap_meta(struct scm *scm) {
    *(size_t *) scm->addr = scm->size.utilized;
}

void *block_addr(void *p) {
    return (char *) p + META_BLOCK_SIZE;
}

short block_bit(void *p) {
    return *(short *) p;
}

size_t block_size(void *p) {
    return *(size_t *) ((char *) p + META_BLOCK_BIT_SIZE);
}

void *next_block_addr(void *p) {
    return (char *) block_addr(p) + block_size(p);
}

void set_block_bit(void *p, short status) {
    *(short *) p = status;
}

void set_block_size(void *p, size_t n) {
    *(size_t *) ((char *) p + META_BLOCK_BIT_SIZE) = n;
}

void set_utilized(struct scm *scm, void *p, short increment) {
    size_t delta = increment * (block_size(p) + META_BLOCK_SIZE);
    scm->size.utilized += delta;

    set_heap_meta(scm);
}

void *scm_malloc(struct scm *scm, size_t n) {
    void *p;
    void *end;

    if (n == 0) {
        TRACE("n is zero");
        return NULL;
    }

    p = base_addr(scm);
    end = (char *) scm->addr + scm->size.capacity;

    while (p < end) {
        if (block_bit(p) == 0) {
            if ((char *) block_addr(p) + n <= (char *) end) {
                set_block_bit(p, 2);
                set_block_size(p, n);
                set_utilized(scm, p, 1);
                return block_addr(p);
            } else {
                break;
            }
        } else if (block_bit(p) == 1) {
            if (block_size(p) >= n) {
                set_block_bit(p, 2);
                set_utilized(scm, p, 1);
                return block_addr(p);
            } else {
                p = next_block_addr(p);
            }
        } else {
            p = next_block_addr(p);
        }
    }

    TRACE("no more space");
    return NULL;
}

char *scm_strdup(struct scm *scm, const char *s) {
    size_t n;
    char *p;

    if (!s) {
        TRACE("s is NULL");
        return NULL;
    }

    n = strlen(s) + 1;
    if (!(p = scm_malloc(scm, n))) {
        TRACE(0);
        return NULL;
    }
    memcpy(p, s, n);

    return p;
}

void scm_free(struct scm *scm, void *p) {
    void *addr = (char *) p - META_BLOCK_SIZE;

    if (block_bit(addr) == 2) {
        set_block_bit(addr, 1);
        set_utilized(scm, addr, -1);
        memset(p, 0, block_size(addr));
    } else {
        TRACE("double free");
    }
}

size_t scm_utilized(const struct scm *scm) {
    return scm->size.utilized;
}

size_t scm_capacity(const struct scm *scm) {
    return scm->size.capacity;
}

void *scm_mbase(struct scm *scm) {
    return block_addr(base_addr(scm));
}
