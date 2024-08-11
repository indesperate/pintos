#include "filesys/cache.h"
#include "threads/synch.h"
#include <list.h>
#include <bitmap.h>
#include <debug.h>
#include "filesys/filesys.h"
#include <string.h>

struct fs_cache_entry {
  block_sector_t sector;  // the cached sector
  struct rw_lock rw_lock; // lock for access entry
  bool occupied;
  // for evict algorithm
  bool accessed;                   // the buffer is accessed, R bit
  bool dirty;                      // the buffer is dirty (writing), W bit
  uint8_t data[BLOCK_SECTOR_SIZE]; // cached buffer
};

#define MAX_FS_BUFFER_SIZE 64

struct fs_cache_buffer {
  struct fs_cache_entry buf[MAX_FS_BUFFER_SIZE];
  int clock_head;
  struct lock lock;
  struct bitmap* load_map;
};

static struct fs_cache_buffer fscb;

void cache_init() {
  // init lock
  lock_init(&fscb.lock);
  for (int i = 0; i < MAX_FS_BUFFER_SIZE; i++) {
    rw_lock_init(&fscb.buf[i].rw_lock);
    fscb.buf[i].accessed = false;
    fscb.buf[i].dirty = false;
    fscb.buf[i].occupied = false;
    fscb.buf[i].sector = -1;
  }
  // create load map
  void* load_map = bitmap_create(block_size(fs_device));
  fscb.clock_head = 0;
  if (load_map == NULL)
    PANIC("bitmap creation failed--the cached the bitmap can't be created");
  fscb.load_map = load_map;
}

static bool is_load(block_sector_t sector) { return bitmap_test(fscb.load_map, sector); }
static void set_load(block_sector_t sector) { bitmap_mark(fscb.load_map, sector); }
static void set_unload(block_sector_t sector) { bitmap_reset(fscb.load_map, sector); }

static struct fs_cache_entry* find_entry(block_sector_t sector) {
  for (int i = 0; i < MAX_FS_BUFFER_SIZE; i++) {
    if (fscb.buf[i].occupied && fscb.buf[i].sector == sector) {
      fscb.buf[i].accessed = true;
      return &fscb.buf[i];
    }
  }
  ASSERT(false);
  return NULL;
}

static void write_back_entry(struct fs_cache_entry* entry) {
  block_write(fs_device, entry->sector, entry->data);
}

static struct fs_cache_entry* evict_entry(void) {
  while (true) {
    if (!fscb.buf[fscb.clock_head].occupied) {
      return &fscb.buf[fscb.clock_head];
    }

    if (fscb.buf[fscb.clock_head].accessed) {
      fscb.buf[fscb.clock_head].accessed = false;
    } else {
      break;
    }

    fscb.clock_head++;
    fscb.clock_head %= MAX_FS_BUFFER_SIZE;
  }

  struct fs_cache_entry* entry = &fscb.buf[fscb.clock_head];
  set_unload(entry->sector);
  fscb.clock_head++;
  fscb.clock_head %= MAX_FS_BUFFER_SIZE;
  if (entry->dirty) {
    write_back_entry(entry);
  }
  entry->occupied = false;

  return entry;
}

void cached_block_read(block_sector_t sector, void* buffer) {
  cached_block_read_at(sector, buffer, BLOCK_SECTOR_SIZE, 0);
}

void cached_block_read_at(block_sector_t sector, void* buffer, size_t size, off_t offset) {
  struct fs_cache_entry* e;
  lock_acquire(&fscb.lock);
  if (is_load(sector)) {
    e = find_entry(sector);
    e->accessed = true;
  } else {
    e = evict_entry();
    e->occupied = true;
    e->accessed = true;
    e->dirty = false;
    e->sector = sector;
    rw_lock_acquire(&e->rw_lock, false);
    block_read(fs_device, sector, e->data);
    rw_lock_release(&e->rw_lock, false);
    set_load(sector);
  }
  lock_release(&fscb.lock);
  rw_lock_acquire(&e->rw_lock, true);
  memcpy(buffer, e->data + offset, size);
  rw_lock_release(&e->rw_lock, true);
}

void cached_block_write(block_sector_t sector, const void* buffer) {
  cached_block_write_at(sector, buffer, BLOCK_SECTOR_SIZE, 0);
}

void cached_block_write_at(block_sector_t sector, const void* buffer, size_t size, off_t offset) {
  struct fs_cache_entry* e;
  lock_acquire(&fscb.lock);
  if (is_load(sector)) {
    e = find_entry(sector);
    e->dirty = true;
  } else {
    e = evict_entry();
    e->occupied = true;
    e->accessed = false;
    e->dirty = true;
    e->sector = sector;
    rw_lock_acquire(&e->rw_lock, false);
    block_read(fs_device, sector, e->data);
    rw_lock_release(&e->rw_lock, false);
    set_load(sector);
  }
  lock_release(&fscb.lock);
  rw_lock_acquire(&e->rw_lock, false);
  memcpy(e->data + offset, buffer, size);
  rw_lock_release(&e->rw_lock, false);
}