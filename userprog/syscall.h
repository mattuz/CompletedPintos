#include <stdbool.h>
#include "threads/thread.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#endif /* userprog/syscall.h */

//int convert_to_kernel_pointer(const void *pointer);

void halt(void);
void exit (int status);
tid_t exec (const char *cmd_line);
bool create (const char *file, unsigned initial_size);
bool remove(const char *file_name);
int open (const char *file);
int file_size(int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close (int fd);
int wait (tid_t child_tid);

void valid_buff(void *buffer, unsigned size);
void valid_addr(void *ptr);
void valid_fd(int fd);
void valid_fd(int fd);

