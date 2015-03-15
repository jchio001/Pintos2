#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

struct lock fs_lock; //our filesystems lock

//used for loading
enum load_state {NOT_LOADED, SUCCESS, FAIL};

//helps out with some of our process functions
struct process_helper {
	struct file* file;
	int fd;
	struct list_elem elem;
};

//how we're containing info related to child processes
struct child_process {
  int pid;
  enum load_state load;
  bool wait;
  bool exit;
  int status;
  struct lock wait_lock;
  struct list_elem elem;
};

//system call foward declarations.
void halt (void);
void exit(int status);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned pos);
unsigned tell (int fd);
void close (int fd);

int user_to_kernel_ptr(const void *vaddr);
void check_valid_ptr (const void *ptr);
struct child_process* add_child_process (int pid);
struct child_process* get_child_process (int pid);
void remove_child_process (struct child_process *cp);
void remove_child_processes (void);

//file-related helper functions
int add_file (struct file *f);
struct file* get_file(int fd);
void close_file (int fd);

void syscall_init (void);

#endif /* userprog/syscall.h */
