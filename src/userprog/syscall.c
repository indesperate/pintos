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
#include "threads/synch.h"
#include "devices/input.h"
#include <float.h>
#include <string.h>

#define SYS_CNT 32

/* init in syscall_init */
struct lock fs_lock;

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

/* check and read byte, error exit */
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

/* check and write one byte, error exit */
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

/* check and read 4 bytes to argc */
static void check_read_or_exit(struct intr_frame* f, uint8_t* argc, uint8_t* uaddr) {
  if (!check_and_read4(argc, uaddr)) {
    error_exit(f, -1);
  }
}

/* check if a valid string */
static void check_str(struct intr_frame* f, uint8_t* uaddr) {
  char c = '\0';
  do {
    if (!check_and_read((uint8_t*)&c, uaddr)) {
      error_exit(f, -1);
    }
    uaddr++;
  } while (c != '\0');
}

/* check buffer can read, only check begin, end and when buffer length over a page size */
static void check_read_buffer(struct intr_frame* f, uint8_t* uaddr, size_t size) {
  uint8_t c;
  if (size > 0) {
    if (!check_and_read(&c, uaddr)) {
      error_exit(f, -1);
    }
    if (!check_and_read(&c, uaddr + size - 1)) {
      error_exit(f, -1);
    }
    while (size > PGSIZE) {
      uaddr += PGSIZE - 1;
      if (!check_and_read(&c, uaddr)) {
        error_exit(f, -1);
      }
      size -= PGSIZE;
    }
  }
}

/* check buffer can write, only check begin and end */
static void check_write_buffer(struct intr_frame* f, uint8_t* uaddr, size_t size) {
  /* int 3(debug interrput x86 asm) assembly code is 0xcc */
  if (size > 0) {
    uint8_t c = 0xcc;
    if (!check_and_write(c, uaddr)) {
      error_exit(f, -1);
    }
    if (!check_and_write(c, uaddr + size - 1)) {
      error_exit(f, -1);
    }
    while (size > PGSIZE) {
      uaddr += PGSIZE - 1;
      if (!check_and_write(c, uaddr)) {
        error_exit(f, -1);
      }
      size -= PGSIZE;
    }
  }
}

static bool check_read_buffer_no_exit(uint8_t* uaddr, size_t size) {
  uint8_t c;
  if (size > 0) {
    if (!check_and_read(&c, uaddr)) {
      return false;
    }
    if (!check_and_read(&c, uaddr + size - 1)) {
      return false;
    }
    while (size > PGSIZE) {
      uaddr += PGSIZE - 1;
      if (!check_and_read(&c, uaddr)) {
        return false;
      }
      size -= PGSIZE;
    }
  }
  return true;
}

static bool check_write_buffer_no_exit(uint8_t* uaddr, size_t size) {
  /* int 3(debug interrput x86 asm) assembly code is 0xcc */
  if (size > 0) {
    uint8_t c = 0xcc;
    if (!check_and_write(c, uaddr)) {
      return false;
    }
    if (!check_and_write(c, uaddr + size - 1)) {
      return false;
    }
    while (size > PGSIZE) {
      uaddr += PGSIZE - 1;
      if (!check_and_write(c, uaddr)) {
        return false;
      }
      size -= PGSIZE;
    }
  }
  return true;
}

static syscall_handler_func* syscall_handlers[SYS_CNT];

static void register_handler(uint8_t vec_no, syscall_handler_func* handler) {
  syscall_handlers[vec_no] = handler;
}

static void sys_exit(struct intr_frame* f) {
  int status;
  uint32_t* args = ((uint32_t*)f->esp);
  check_read_or_exit(f, (uint8_t*)&status, (uint8_t*)&args[1]);
  thread_current()->pcb->child_ptr->exit_status = status;
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
  lock_acquire(&thread_current()->pcb->fds_lock);
  struct file* open_file = filesys_open(file);
  if (!open_file) {
    f->eax = -1;
    lock_release(&thread_current()->pcb->fds_lock);
    return;
  }
  /* set fds */
  struct file_descriptor* fdp = malloc(sizeof(struct file_descriptor));
  if (fdp == NULL) {
    file_close(open_file);
    lock_release(&thread_current()->pcb->fds_lock);
    f->eax = -1;
    return;
  }
  struct list* fds = &thread_current()->pcb->fds;
  int fd = 2;
  if (!list_empty(fds)) {
    struct file_descriptor* end = list_entry(list_back(fds), struct file_descriptor, elem);
    fd = end->fd + 1;
  }
  fdp->fd = fd;
  fdp->file = open_file;
  lock_init(&fdp->lock);
  list_push_back(fds, &fdp->elem);
  lock_release(&thread_current()->pcb->fds_lock);
  f->eax = fd;
}

/* find the fd -> file_descriptor in fds */
static struct file_descriptor* find_fd(int fd) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO) {
    return NULL;
  }
  lock_acquire(&thread_current()->pcb->fds_lock);
  struct list_elem* e;
  struct list* fds = &thread_current()->pcb->fds;
  for (e = list_begin(fds); e != list_end(fds); e = list_next(e)) {
    struct file_descriptor* f = list_entry(e, struct file_descriptor, elem);
    if (f->fd == fd) {
      lock_release(&thread_current()->pcb->fds_lock);
      return f;
    }
  }
  lock_release(&thread_current()->pcb->fds_lock);
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
  lock_acquire(&fdp->lock);
  f->eax = file_length(fdp->file);
  lock_release(&fdp->lock);
}

static void sys_close(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd;
  check_read_or_exit(f, (uint8_t*)&fd, (uint8_t*)&args[1]);
  struct file_descriptor* fdp = find_fd(fd);
  if (!fdp) {
    error_exit(f, -1);
  }
  lock_acquire(&thread_current()->pcb->fds_lock);
  file_close(fdp->file);
  list_remove(&fdp->elem);
  lock_release(&thread_current()->pcb->fds_lock);
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
    /* check fd */
    if (!fdp) {
      error_exit(f, -1);
    }
    /* buffer write */
    lock_acquire(&fdp->lock);
    num_read += file_read(fdp->file, buffer, size);
    lock_release(&fdp->lock);
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
    /* buffer write */
    putbuf(buffer, size);
    num_writen += size;
  } else {
    struct file_descriptor* fdp = find_fd(fd);
    if (!fdp) {
      error_exit(f, -1);
    }
    /* buffer write */
    lock_acquire(&fdp->lock);
    num_writen += file_write(fdp->file, buffer, size);
    lock_release(&fdp->lock);
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
  lock_acquire(&fdp->lock);
  file_seek(fdp->file, position);
  lock_release(&fdp->lock);
}

static void sys_tell(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd;
  check_read_or_exit(f, (uint8_t*)&fd, (uint8_t*)&args[1]);
  struct file_descriptor* fdp = find_fd(fd);
  if (!fdp) {
    error_exit(f, -1);
  }
  lock_acquire(&fdp->lock);
  f->eax = file_tell(fdp->file);
  lock_release(&fdp->lock);
}

/* floating point opeartions */
static void sys_compute_e(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  int n;
  check_read_or_exit(f, (uint8_t*)&n, (uint8_t*)&args[1]);
  f->eax = sys_sum_to_e(n);
}

static void sys_pt_create(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  stub_fun sfun;
  pthread_fun tfun;
  void* arg;
  check_read_or_exit(f, (uint8_t*)&sfun, (uint8_t*)&args[1]);
  check_read_or_exit(f, (uint8_t*)&tfun, (uint8_t*)&args[2]);
  check_read_or_exit(f, (uint8_t*)&arg, (uint8_t*)&args[3]);
  f->eax = pthread_execute(sfun, tfun, arg);
}

static void sys_pt_exit(struct intr_frame* f) {
  pthread_exit();
  if (is_main_thread(thread_current(), thread_current()->pcb)) {
    f->eax = 0;
    if (thread_current()->tid == -1) {
      thread_exit();
    }
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, 0);
    process_exit();
  }
}

static void sys_pt_join(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  tid_t tid;
  check_read_or_exit(f, (uint8_t*)&tid, (uint8_t*)&args[1]);
  f->eax = pthread_join(tid);
}

static void sys_lock_init(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  lock_t* lock;
  check_read_or_exit(f, (uint8_t*)&lock, (uint8_t*)&args[1]);
  if (!check_write_buffer_no_exit(lock, 1)) {
    return false;
  };
  struct user_lock* u_lock = malloc(sizeof(struct user_lock));
  lock_init(&u_lock->lock);
  if (u_lock == NULL) {
    f->eax = false;
    return;
  }
  int id = 0;
  struct process* pcb = thread_current()->pcb;
  struct list* u_locks = &pcb->locks;
  lock_acquire(&pcb->thread_lock);
  if (!list_empty(u_locks)) {
    struct user_lock* end = list_entry(list_back(u_locks), struct user_lock, elem);
    id = end->id + 1;
  }
  u_lock->id = id;
  list_push_back(&pcb->locks, &u_lock->elem);
  lock_release(&pcb->thread_lock);
  *lock = id;
  f->eax = true;
}

static struct user_lock* find_user_lock(lock_t u_lock) {
  struct list_elem* e;
  struct list* locks = &thread_current()->pcb->locks;
  for (e = list_begin(locks); e != list_end(locks); e = list_next(e)) {
    struct user_lock* l = list_entry(e, struct user_lock, elem);
    if (l->id == u_lock) {
      return l;
    }
  }
  return NULL;
};

static void sys_lock_acquire(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  lock_t* lock;
  check_read_or_exit(f, (uint8_t*)&lock, (uint8_t*)&args[1]);
  if (!check_read_buffer_no_exit(lock, 1)) {
    f->eax = false;
    return;
  }
  struct process* pcb = thread_current()->pcb;
  /* get user lock */
  struct user_lock* u_lock = NULL;
  lock_acquire(&pcb->thread_lock);
  u_lock = find_user_lock(*lock);
  lock_release(&pcb->thread_lock);
  /* lock not valid or acquire failed */
  if (u_lock == NULL || lock_held_by_current_thread(&u_lock->lock)) {
    f->eax = false;
    return;
  }
  lock_acquire(&u_lock->lock);
  f->eax = true;
}

static void sys_lock_release(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  lock_t* lock;
  check_read_or_exit(f, (uint8_t*)&lock, (uint8_t*)&args[1]);
  if (!check_read_buffer_no_exit(lock, 1)) {
    f->eax = false;
    return;
  }
  struct process* pcb = thread_current()->pcb;
  /* get user lock */
  struct user_lock* u_lock = NULL;
  lock_acquire(&pcb->thread_lock);
  u_lock = find_user_lock(*lock);
  lock_release(&pcb->thread_lock);
  /* lock not valid or acquire failed */
  if (u_lock == NULL || !lock_held_by_current_thread(&u_lock->lock)) {
    f->eax = false;
    return;
  }
  lock_release(&u_lock->lock);
  f->eax = true;
}

static void sys_sema_init(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  sema_t* sema;
  int val;
  check_read_or_exit(f, (uint8_t*)&sema, (uint8_t*)&args[1]);
  check_read_or_exit(f, (uint8_t*)&val, (uint8_t*)&args[2]);
  if (!check_write_buffer_no_exit(sema, 1)) {
    return false;
  };
  struct user_sema* u_sema = malloc(sizeof(struct user_sema));
  sema_init(&u_sema->sema, val);
  if (u_sema == NULL || val < 0) {
    f->eax = false;
    return;
  }
  int id = 0;
  struct process* pcb = thread_current()->pcb;
  struct list* u_semas = &pcb->semas;
  lock_acquire(&pcb->thread_lock);
  if (!list_empty(u_semas)) {
    struct user_sema* end = list_entry(list_back(u_semas), struct user_sema, elem);
    id = end->id + 1;
  }
  u_sema->id = id;
  list_push_back(&pcb->semas, &u_sema->elem);
  lock_release(&pcb->thread_lock);
  *sema = id;
  f->eax = true;
}

static struct user_sema* find_user_sema(sema_t u_sema) {
  struct list_elem* e;
  struct list* semas = &thread_current()->pcb->semas;
  for (e = list_begin(semas); e != list_end(semas); e = list_next(e)) {
    struct user_sema* l = list_entry(e, struct user_sema, elem);
    if (l->id == u_sema) {
      return l;
    }
  }
  return NULL;
};

static void sys_sema_down(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  sema_t* sema;
  check_read_or_exit(f, (uint8_t*)&sema, (uint8_t*)&args[1]);
  if (!check_read_buffer_no_exit(sema, 1)) {
    f->eax = false;
    return;
  }
  struct process* pcb = thread_current()->pcb;
  /* get user sema */
  struct user_sema* u_sema = NULL;
  lock_acquire(&pcb->thread_lock);
  u_sema = find_user_sema(*sema);
  lock_release(&pcb->thread_lock);
  /* sema not valid or acquire failed */
  if (u_sema == NULL) {
    f->eax = false;
    return;
  }
  sema_down(&u_sema->sema);
  f->eax = true;
}

static void sys_sema_up(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  sema_t* sema;
  check_read_or_exit(f, (uint8_t*)&sema, (uint8_t*)&args[1]);
  if (!check_read_buffer_no_exit(sema, 1)) {
    f->eax = false;
    return;
  }
  struct process* pcb = thread_current()->pcb;
  /* get user sema */
  struct user_sema* u_sema = NULL;
  lock_acquire(&pcb->thread_lock);
  u_sema = find_user_sema(*sema);
  lock_release(&pcb->thread_lock);
  /* sema not valid or acquire failed */
  if (u_sema == NULL) {
    f->eax = false;
    return;
  }
  sema_up(&u_sema->sema);
  f->eax = true;
}

static void sys_get_tid(struct intr_frame* f) { f->eax = thread_current()->tid; }

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
  register_handler(SYS_PT_CREATE, sys_pt_create);
  register_handler(SYS_PT_EXIT, sys_pt_exit);
  register_handler(SYS_PT_JOIN, sys_pt_join);
  register_handler(SYS_LOCK_INIT, sys_lock_init);
  register_handler(SYS_LOCK_ACQUIRE, sys_lock_acquire);
  register_handler(SYS_LOCK_RELEASE, sys_lock_release);
  register_handler(SYS_SEMA_INIT, sys_sema_init);
  register_handler(SYS_SEMA_DOWN, sys_sema_down);
  register_handler(SYS_SEMA_UP, sys_sema_up);
  register_handler(SYS_GET_TID, sys_get_tid);
  register_handler(SYS_MMAP, dump);
  register_handler(SYS_MUNMAP, dump);
  register_handler(SYS_CHDIR, dump);
  register_handler(SYS_MKDIR, dump);
  register_handler(SYS_READDIR, dump);
  register_handler(SYS_ISDIR, dump);
  register_handler(SYS_INUMBER, dump);
  /* file system global lock */
  lock_init(&fs_lock);
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
