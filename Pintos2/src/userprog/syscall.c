#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

//I have no idea why, but if I move this declaration to syscall.h, 
//I get a ton of warnings and errors. But if I leave it here, everything's
//fine. What?
static void syscall_handler (struct intr_frame *);
//compiler also spazzes out if anything with pid_t is in syscall.h. ???
pid_t exec(const char *cmd_line);
int wait (pid_t pid);

void
syscall_init (void) 
{
  lock_init(&fs_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int i = 0;
  int arg[4];
  //PARSING STUFF INTO ARG HERE!!1    
  for (i; i < 4; i++)    
      arg[i] = * ((int *) f->esp + i);  
  
  switch (arg[0]) {
    case SYS_HALT:      
		halt(); 
		break;      
    case SYS_EXIT:      
		exit(arg[1]);
		break;      
	case SYS_EXEC:      
		arg[1] = user_to_kernel_ptr((const void *) arg[1]);
		f->eax = exec((const char *) arg[1]); 
		break;      
    case SYS_WAIT:
		f->eax = wait(arg[1]);
		break;      
    case SYS_CREATE:      
		arg[1] = user_to_kernel_ptr((const void *) arg[1]);
		f->eax = create((const char *)arg[1], (unsigned) arg[2]);
		break;      
    case SYS_REMOVE:
		arg[1] = user_to_kernel_ptr((const void *) arg[1]);
		f->eax = remove((const char *) arg[1]);
		break;      
    case SYS_OPEN:      
		arg[1] = user_to_kernel_ptr((const void *) arg[1]);
		f->eax = open((const char *) arg[1]);
		break; 		      
    case SYS_FILESIZE:      
		f->eax = filesize(arg[1]);
		break;      
    case SYS_READ:      
		arg[2] = user_to_kernel_ptr((const void *) arg[2]);
		f->eax = read(arg[1], (void *) arg[2], (unsigned) arg[3]);
		break;      
    case SYS_WRITE:      
		arg[2] = user_to_kernel_ptr((const void *) arg[2]);
		f->eax = write(arg[1], (const void *) arg[2], (unsigned) arg[3]);
		break;              
    case SYS_TELL:      
		f->eax = tell(arg[1]);
		break;
	case SYS_SEEK:      
		seek(arg[1], (unsigned) arg[2]);
		break;
    case SYS_CLOSE:      
		close(arg[1]);
		break;
	default:		
		break;
    }
}

void halt (void) {
  shutdown_power_off();
}

void exit(int status) {	
	struct thread* cur = thread_current();
	//cp sounds very awkward, but it's the simplest way to say child process
	if (thread_alive(cur->parent_id) && (cur->cp != NULL))
		cur->cp->status = status;
	
	printf ("%s: exit(%d)\n", cur->name, status);
	thread_exit();	
}

pid_t exec (const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  struct child_process* child = get_child_process(pid);
  
  if (child == NULL)
		return -1;
  
  //busy waiting fun
  while (child->load == NOT_LOADED)    
      thread_yield();      
          
  if (child->load == FAIL)    
      return -1;
        
  return pid;
}

int wait (pid_t pid) {
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
  lock_acquire(&fs_lock);
  bool create_succ = filesys_create(file, initial_size);
  lock_release(&fs_lock);
  return create_succ;
}

bool remove (const char *file) {
  lock_acquire(&fs_lock);
  bool remove_succ = filesys_remove(file);
  lock_release(&fs_lock);
  return remove_succ;
}

int open (const char *file) {
  lock_acquire(&fs_lock);
  struct file *f = filesys_open(file);
  if (f == NULL) {
      lock_release(&fs_lock);
      return -1;
  }
  int fd = add_file(f);
  lock_release(&fs_lock);
  return fd;
}

void close (int fd) {
  lock_acquire(&fs_lock);
  close_file(fd);
  lock_release(&fs_lock);
}

int filesize (int fd) {	
  lock_acquire(&fs_lock);
  struct file *f = get_file(fd);
  
  if (f == NULL) {
      lock_release(&fs_lock);
      return -1;
  }
  
  int len = file_length(f);
  lock_release(&fs_lock);
  return len;
}

int read (int fd, void *buffer, unsigned size) {
  unsigned counter = 0;
  uint8_t* buff = (uint8_t *) buffer;
  if (fd == 0) {
      for (; counter < size; counter++) {
	  buff[counter] = input_getc();
      }
      return size;
   }
   
  lock_acquire(&fs_lock);
  struct file *f = get_file(fd);
  if (f == NULL) {
      lock_release(&fs_lock);
      return -1;
  }
  
  int read_bytes = file_read(f, buffer, size);
  lock_release(&fs_lock);
  return read_bytes;
}

int write (int fd, const void *buffer, unsigned size) {
  
  if (fd == 1) {
      putbuf(buffer, size);
      return size;
  }
  
  lock_acquire(&fs_lock);
  struct file *f = get_file(fd);
  if (f == NULL) {
      lock_release(&fs_lock);
      return -1;
  }
  int write_bytes = file_write(f, buffer, size);
  lock_release(&fs_lock);
  return write_bytes;
}

void seek (int fd, unsigned pos) {
  lock_acquire(&fs_lock);
  struct file *f = get_file(fd);
  if (f == NULL) {
      lock_release(&fs_lock);
      return;
  }
  file_seek(f, pos);
  lock_release(&fs_lock);
}

unsigned tell (int fd) {
  lock_acquire(&fs_lock);
  struct file *f = get_file(fd);
  
  if (f == NULL) {
      lock_release(&fs_lock);
      return -1;
  }
  
  //off_t = 32 bit integer. Defined in off_t.h.
  off_t offset = file_tell(f);
  lock_release(&fs_lock);
  return offset;
}

void check_valid_ptr (const void *ptr) {
	//0x08048000 is the bottom address of our virtual address space
	if (!is_user_vaddr(ptr) || ptr < 0x08048000){
		exit(-1);
	}
}

int user_to_kernel_ptr (const void *addr) {
	struct thread *cur = thread_current();
	check_valid_ptr(addr);
	void  *ptr = pagedir_get_page(cur->pagedir, addr);
	if (ptr == NULL)
		exit(-1);

	return (int) ptr;
}


int add_file (struct file *f) {
	//I could use simpler names for variables, but when I debug, sometimes having file names
	//with more than 2 letters speeds up my thinking.
	struct process_helper *proc_file = malloc(sizeof(struct process_helper));
	if (proc_file == NULL)
		return -1;
		
  	proc_file->file = f;
  	proc_file->fd = thread_current()->fd;
  	(thread_current()->fd)++;
  	list_push_back(&thread_current()->file_list, &proc_file->elem);
  	return proc_file->fd;
}

struct file* get_file(int fd) {
	struct thread  *cur = thread_current();
	struct list_elem *cntr = list_begin(&cur->file_list);
	struct process_helper *ph;

	for (; cntr != list_end(&cur->file_list); cntr = list_next(cntr)) {
		ph = list_entry(cntr, struct process_helper, elem);
		if (fd == ph->fd)
			return ph->file;
	}
	//If we are unable to obtain the file, we want to return NULL because
	//whatever function calling process_get_file will probably check for NULL
	//and crash, as me + my partner have seen from our numerous attempts at 
	//Pintos.
	return NULL;
}

void close_file (int fd) {
  struct thread *cur = thread_current();
  struct list_elem *iterator = list_begin(&cur->file_list);

  struct list_elem *next;
  for (;iterator != list_end (&cur->file_list); iterator = next) {
      next = list_next(iterator);
      struct process_helper *ph = list_entry (iterator, struct process_helper, elem);
      
      bool sameFD = (fd == ph->fd);
      bool closeFile = (fd == -1);
      
      if (sameFD || closeFile) {
	  file_close(ph->file);
	  list_remove(&ph->elem);
	  free(ph);
	  if (fd > -1)
	      return;
	    
      }
   }
}

struct child_process* add_child_process (int pid) {

	struct child_process* cp = malloc(sizeof(struct child_process));
	if (cp == NULL)
		return NULL;

	cp->pid = pid;
	cp->load = NOT_LOADED;
	lock_init(&cp->wait_lock);
	cp->wait = false;
	cp->exit = false;	
	
	struct thread *cur = thread_current();
	list_push_back(&cur->child_list, &cp->elem);
	return cp;	
}

struct child_process* get_child_process(int pid) {
	struct thread *cur = thread_current();
	struct list_elem *cntr = list_begin(&cur->child_list);
	struct child_process *child;	

	for (; cntr != list_end(&cur->child_list); cntr = list_next(cntr)) {
		child = list_entry(cntr, struct child_process, elem);
		if (pid == child->pid)
			return child;
	}
	
	return NULL;
}
void remove_child_process (struct child_process *cp) {
  list_remove(&cp->elem);
  free(cp);
}

void remove_child_processes (void) {
  struct thread *cur = thread_current();
  struct list_elem *next;
  struct list_elem *cntr = list_begin(&cur->child_list);

  //I know just putting cntr has no effect, but putting it here looks cleaner for my eyes
  for (cntr; cntr != list_end (&cur->child_list); cntr = next) {
      next = list_next(cntr);
      struct child_process *cp = list_entry (cntr, struct child_process, elem);
      list_remove(&cp->elem);
      free(cp);
      cntr = next;
  }
  
 }
