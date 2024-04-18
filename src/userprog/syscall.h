#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

typedef void syscall_handler_func(struct intr_frame*);

#endif /* userprog/syscall.h */
