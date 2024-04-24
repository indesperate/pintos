#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

struct file_descriptor {
  int fd;
  struct file* file;
  struct list_elem elem;
};

/* porcess child parent shared data */
struct process_cps_data {
  pid_t pid;             /* children tid */
  struct list_elem elem; /* list elem */
  /* only for userprog processes */
  struct semaphore wait_sema; /* semaphore to wait child process*/
  int exit_status;            /* exit status */
  bool wait_called;           /* if already called wait*/
};

struct pthread_data {
  tid_t tid;                  /* child thread*/
  struct list_elem elem;      /* list elem */
  struct semaphore wait_sema; /* semaphore to wait child pthread*/
  uint8_t* stack;             /* pthread stack */
  bool waited;
};

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;                  /* Page directory. */
  char process_name[16];              /* Name of the main thread */
  struct thread* main_thread;         /* Pointer to main thread */
  struct list fds;                    /* file descriptors list*/
  struct file* exec_file;             /* executable file resource */
  struct list child_processes;        /* process children list */
  struct list pthreads;               /* process pthreads list */
  struct process_cps_data* child_ptr; /* child ptr in parent */
  uint8_t* stack_begin;               /* stack start virtual address for allocate */
  struct lock thread_lock;            /* lock when access process data */
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
