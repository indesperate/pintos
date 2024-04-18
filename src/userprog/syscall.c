#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"

#define SYS_CNT 32
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

/* read 4 bytes */
static bool check_and_read4(uint8_t* argc, const uint8_t* uaddr) {
  for (int i = 0; i < 4; i++) {
    if (!is_user_vaddr(uaddr)) {
      return false;
    }
    int result = get_user(uaddr);
    if (result == -1) {
      return false;
    }
    *argc = (uint8_t)result;
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

static syscall_handler_func* syscall_handlers[SYS_CNT];

static void register_handler(uint8_t vec_no, syscall_handler_func* handler) {
  syscall_handlers[vec_no] = handler;
}

static void sys_exit(struct intr_frame* f) {
  int status;
  uint32_t* args = ((uint32_t*)f->esp);
  check_read_or_exit(f, (uint8_t*)&status, (uint8_t*)&args[1]);
  thread_current()->return_stauts = status;
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
  char* cmd_line;
  check_read_or_exit(f, (uint8_t*)&cmd_line, (uint8_t*)&args[1]);
  f->eax = process_execute(cmd_line);
}
static void sys_wait(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  pid_t pid;
  check_read_or_exit(f, (uint8_t*)&pid, (uint8_t*)&args[1]);
  f->eax = process_wait(pid);
}

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  register_handler(SYS_HALT, sys_halt);
  register_handler(SYS_EXIT, sys_exit);
  register_handler(SYS_EXEC, sys_exec);
  register_handler(SYS_WAIT, sys_wait);
  register_handler(SYS_CREATE, dump);
  register_handler(SYS_REMOVE, dump);
  register_handler(SYS_OPEN, dump);
  register_handler(SYS_FILESIZE, dump);
  register_handler(SYS_READ, dump);
  register_handler(SYS_WRITE, dump);
  register_handler(SYS_SEEK, dump);
  register_handler(SYS_TELL, dump);
  register_handler(SYS_CLOSE, dump);
  register_handler(SYS_PRACTICE, sys_practice);
  register_handler(SYS_COMPUTE_E, dump);
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