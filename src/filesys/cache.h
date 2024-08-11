#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "filesys/off_t.h"

void cached_block_write_at(block_sector_t sector, const void* buffer, size_t size, off_t offset);
void cached_block_read_at(block_sector_t sector, void* buffer, size_t size, off_t offset);
void cached_block_write(block_sector_t sector, const void* buffer);
void cached_block_read(block_sector_t sector, void* buffer);
void cache_init(void);

#endif /* filesys/cache.h */