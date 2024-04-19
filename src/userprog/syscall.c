#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include <float.h>
#include <string.h>

#define SYS_CNT 32
#define MAX_BUF 256

typedef void syscall_handler_func(struct intr_frame*);

static void syscall_handler(struct intr_frame*);

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful,
   -1 if a segfault occurred. */
static int get_user(const uint8_t* uaddr) {
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful,
   false if a segfault occurred. */
UNUSED static bool put_user(uint8_t* udst, uint8_t byte) {
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:" : "=&a"(error_code), "=m"(*udst) : "q"(byte));
  return error_code != -1;
}

static bool check_and_read(uint8_t* argc, const uint8_t* uaddr) {
  if (!is_user_vaddr(uaddr)) {
    return false;
  }
  int result = get_user(uaddr);
  if (result == -1) {
    return false;
  }
  *argc = (uint8_t)result;
  return true;
}

static bool check_and_write(uint8_t argc, uint8_t* uaddr) {
  if (!is_user_vaddr(uaddr) || !put_user(uaddr, argc)) {
    return false;
  }
  return true;
}

/* read 4 bytes */
static bool check_and_read4(uint8_t* argc, const uint8_t* uaddr) {
  for (int i = 0; i < 4; i++) {
    if (!check_and_read(argc, uaddr)) {
      return false;
    }
    argc++;
    uaddr++;
  }
  return true;
}

static void error_exit(struct intr_frame* f, int error_code) {
  f->eax = error_code;
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, error_code);
  process_exit();
}

static void check_read_or_exit(struct intr_frame* f, uint8_t* argc, uint8_t* uaddr) {
  if (!check_and_read4(argc, uaddr)) {
    error_exit(f, -1);
  }
}

static void check_str(struct intr_frame* f, uint8_t* uaddr) {
  char c = '\0';
  do {
    if (!check_and_read((uint8_t*)&c, uaddr)) {
      error_exit(f, -1);
    }
    uaddr++;
  } while (c != '\0');
}

static void check_read_buffer(struct intr_frame* f, uint8_t* uaddr, size_t size) {
  uint8_t c;
  for (size_t i = 0; i < size; i++) {
    if (!check_and_read(&c, uaddr)) {
      error_exit(f, -1);
    }
    uaddr++;
  }
}

static void check_write_buffer(struct intr_frame* f, uint8_t* uaddr, size_t size) {
  uint8_t c = 'c';
  for (size_t i = 0; i < size; i++) {
    if (!check_and_write(c, uaddr)) {
      error_exit(f, -1);
    }
    uaddr++;
  }
}

static syscall_handler_func* syscall_handlers[SYS_CNT];

static void register_handler(uint8_t vec_no, syscall_handler_func* handler) {
  syscall_handlers[vec_no] = handler;
}

static void sys_exit(struct intr_frame* f) {
  int status;
  uint32_t* args = ((uint32_t*)f->esp);
  check_read_or_exit(f, (uint8_t*)&status, (uint8_t*)&args[1]);
  ASSERT(thread_current()->child_ptr != NULL);
  thread_current()->child_ptr->exit_status = status;
  error_exit(f, status);
}

static void dump(struct intr_frame* f) {
  printf("Not implemetned\n");
  error_exit(f, -1);
}

static void sys_practice(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int i;
  check_read_or_exit(f, (uint8_t*)&i, (uint8_t*)&args[1]);
  f->eax = i + 1;
}

static void sys_halt(struct intr_frame* f UNUSED) { shutdown_power_off(); }

static void sys_exec(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  const char* cmd_line;
  check_read_or_exit(f, (uint8_t*)&cmd_line, (uint8_t*)&args[1]);
  check_str(f, (uint8_t*)cmd_line);
  f->eax = process_execute(cmd_line);
}
static void sys_wait(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  pid_t pid;
  check_read_or_exit(f, (uint8_t*)&pid, (uint8_t*)&args[1]);
  f->eax = process_wait(pid);
}

static void sys_create(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  const char* file;
  unsigned initial_size;
  check_read_or_exit(f, (uint8_t*)&file, (uint8_t*)&args[1]);
  check_read_or_exit(f, (uint8_t*)&initial_size, (uint8_t*)&args[2]);
  check_str(f, (uint8_t*)file);
  if (!strcmp(file, "")) {
    error_exit(f, -1);
  }
  f->eax = filesys_create(file, initial_size);
}

static void sys_remove(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  const char* file;
  check_read_or_exit(f, (uint8_t*)&file, (uint8_t*)&args[1]);
  check_str(f, (uint8_t*)file);
  if (!strcmp(file, "")) {
    error_exit(f, -1);
  }
  f->eax = filesys_remove(file);
}

static void sys_open(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  const char* file;
  check_read_or_exit(f, (uint8_t*)&file, (uint8_t*)&args[1]);
  check_str(f, (uint8_t*)file);
  struct file* open_file = filesys_open(file);
  if (!open_file) {
    f->eax = -1;
    return;
  }
  struct file_descriptor* fdp = malloc(sizeof(struct file_descriptor));
  struct list* fds = &thread_current()->fds;
  int fd = 2;
  if (!list_empty(fds)) {
    struct file_descriptor* end = list_entry(list_back(fds), struct file_descriptor, elem);
    fd = end->fd + 1;
  }
  fdp->fd = fd;
  fdp->file = open_file;
  list_push_back(fds, &fdp->elem);
  f->eax = fd;
}

static struct file_descriptor* find_fd(int fd) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO) {
    return NULL;
  }
  struct list_elem* e;
  struct list* fds = &thread_current()->fds;
  for (e = list_begin(fds); e != list_end(fds); e = list_next(e)) {
    struct file_descriptor* f = list_entry(e, struct file_descriptor, elem);
    if (f->fd == fd) {
      return f;
    }
  }
  return NULL;
}

static void sys_filesize(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd;
  check_read_or_exit(f, (uint8_t*)&fd, (uint8_t*)&args[1]);
  struct file_descriptor* fdp = find_fd(fd);
  if (!fdp) {
    f->eax = -1;
  }
  f->eax = file_length(fdp->file);
}

static void sys_close(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd;
  check_read_or_exit(f, (uint8_t*)&fd, (uint8_t*)&args[1]);
  struct file_descriptor* fdp = find_fd(fd);
  if (!fdp) {
    error_exit(f, -1);
  }
  file_close(fdp->file);
  list_remove(&fdp->elem);
  free(fdp);
}
static void sys_read(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd;
  void* buffer;
  unsigned size;
  check_read_or_exit(f, (uint8_t*)&fd, (uint8_t*)&args[1]);
  check_read_or_exit(f, (uint8_t*)&buffer, (uint8_t*)&args[2]);
  check_read_or_exit(f, (uint8_t*)&size, (uint8_t*)&args[3]);
  check_write_buffer(f, buffer, size);
  int num_read = 0;
  if (fd == STDIN_FILENO) {
    while (size > 1) {
      *((uint8_t*)buffer) = input_getc();
      buffer = (uint8_t*)buffer + 1;
      num_read += 1;
      size -= 1;
    }
    *((uint8_t*)buffer) = input_getc();
    num_read += 1;
  } else {
    struct file_descriptor* fdp = find_fd(fd);
    if (!fdp) {
      error_exit(f, -1);
    }
    while (size > MAX_BUF) {
      num_read += file_read(fdp->file, buffer, MAX_BUF);
      size -= MAX_BUF;
    }
    num_read += file_read(fdp->file, buffer, size);
  }
  f->eax = num_read;
  return;
}

static void sys_write(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd;
  void* buffer;
  unsigned size;
  check_read_or_exit(f, (uint8_t*)&fd, (uint8_t*)&args[1]);
  check_read_or_exit(f, (uint8_t*)&buffer, (uint8_t*)&args[2]);
  check_read_or_exit(f, (uint8_t*)&size, (uint8_t*)&args[3]);
  check_read_buffer(f, buffer, size);
  int num_writen = 0;
  if (fd == STDOUT_FILENO) {
    while (size > MAX_BUF) {
      putbuf(buffer, MAX_BUF);
      buffer = (uint8_t*)buffer + MAX_BUF;
      num_writen += MAX_BUF;
      size -= MAX_BUF;
    }
    putbuf(buffer, size);
    num_writen += size;
  } else {
    struct file_descriptor* fdp = find_fd(fd);
    if (!fdp) {
      error_exit(f, -1);
    }
    while (size > MAX_BUF) {
      num_writen += file_write(fdp->file, buffer, MAX_BUF);
      size -= MAX_BUF;
    }
    num_writen += file_write(fdp->file, buffer, size);
  }
  f->eax = num_writen;
  return;
}

static void sys_seek(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd;
  unsigned position;
  check_read_or_exit(f, (uint8_t*)&fd, (uint8_t*)&args[1]);
  check_read_or_exit(f, (uint8_t*)&position, (uint8_t*)&args[2]);
  struct file_descriptor* fdp = find_fd(fd);
  if (!fdp) {
    error_exit(f, -1);
  }
  file_seek(fdp->file, position);
}

static void sys_tell(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd;
  check_read_or_exit(f, (uint8_t*)&fd, (uint8_t*)&args[1]);
  struct file_descriptor* fdp = find_fd(fd);
  if (!fdp) {
    error_exit(f, -1);
  }
  f->eax = file_tell(fdp->file);
}

/* floating point opeartions */
static void sys_compute_e(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int n;
  check_read_or_exit(f, (uint8_t*)&n, (uint8_t*)&args[1]);
  f->eax = sys_sum_to_e(n);
}

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  register_handler(SYS_HALT, sys_halt);
  register_handler(SYS_EXIT, sys_exit);
  register_handler(SYS_EXEC, sys_exec);
  register_handler(SYS_WAIT, sys_wait);
  register_handler(SYS_CREATE, sys_create);
  register_handler(SYS_REMOVE, sys_remove);
  register_handler(SYS_OPEN, sys_open);
  register_handler(SYS_FILESIZE, sys_filesize);
  register_handler(SYS_READ, sys_read);
  register_handler(SYS_WRITE, sys_write);
  register_handler(SYS_SEEK, sys_seek);
  register_handler(SYS_TELL, sys_tell);
  register_handler(SYS_CLOSE, sys_close);
  register_handler(SYS_PRACTICE, sys_practice);
  register_handler(SYS_COMPUTE_E, sys_compute_e);
  register_handler(SYS_PT_CREATE, dump);
  register_handler(SYS_PT_EXIT, dump);
  register_handler(SYS_PT_JOIN, dump);
  register_handler(SYS_LOCK_INIT, dump);
  register_handler(SYS_LOCK_ACQUIRE, dump);
  register_handler(SYS_LOCK_RELEASE, dump);
  register_handler(SYS_SEMA_INIT, dump);
  register_handler(SYS_SEMA_DOWN, dump);
  register_handler(SYS_SEMA_UP, dump);
  register_handler(SYS_MMAP, dump);
  register_handler(SYS_MUNMAP, dump);
  register_handler(SYS_CHDIR, dump);
  register_handler(SYS_MKDIR, dump);
  register_handler(SYS_READDIR, dump);
  register_handler(SYS_ISDIR, dump);
  register_handler(SYS_INUMBER, dump);
}

static void syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */
  int call_number;
  check_read_or_exit(f, (uint8_t*)&call_number, (uint8_t*)args);

  syscall_handler_func* handler = syscall_handlers[call_number];
  if (handler) {
    handler(f);
  } else {
    error_exit(f, -1);
  }
}
