#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

struct lock fs_lock;
enum load_state {NOT_LOADED, SUCCESS, FAIL};

struct process_helper {
	struct file* file;
	int fd;
	struct list_elem elem;
};

struct child_process {
  int pid;
  enum load_state load;
  bool wait;
  bool exit;
  int status;
  struct lock wait_lock;
  struct list_elem elem;
};

int process_add_file (struct file *f);
struct file* process_get_file (int fd);
int user_to_kernel_ptr(const void *vaddr);

void check_valid_ptr (const void *ptr);
struct child_process* add_child_process (int pid);
struct child_process* get_child_process (int pid);
void remove_child_process (struct child_process *cp);
void remove_child_processes (void);

void process_close_file (int fd);

void syscall_init (void);

#endif /* userprog/syscall.h */