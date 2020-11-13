#include "userprog/syscall.h"
#include <stdio.h>
#include <list.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "pagedir.h"

#define USER_BOTTOM ((void*) 0x08048000)

typedef int pid_t;
static struct list list_fds;

struct file_descriptor
{
  int fd_id;
  tid_t owner;
  struct file* File;
  struct list_elem elem; 
};

static void syscall_handler (struct intr_frame *);

void halt(void) {
  shutdown_power_off();
}

pid_t exec(const char *cmd_line) {
}

int wait(pid_t pid) {
}

bool create(const char *file, unsigned initial_size) {
}

bool remove(const char *file) {
}

int open(const char *file) {
	//fd = filesys open para abrir el file
	//palloc en page 
	//hacer que el fd 
 }

int filesize(int fd) {
}

int read(int fd, void *buffer, unsigned length) {
}

int write(int fd, const void *buffer, unsigned size) {
	check_ptr(buffer);
  //struct list_elem* iter = list_begin(&list_fds);
  struct file* theFile = NULL;
	theFile = palloc_get_page(0);
  /*while (iter != list_end(&list_fds)) {
    struct file_descriptor* fi_desc= list_entry(iter, struct file_descriptor, elem);   
    if (fd == fi_desc->fd_id) {
    	theFile = palloc_get_page(0);
      theFile = fi_desc->File;
      break;
    }
    iter = list_next(iter);
  }*/
  if (fd == 1) 
	{
    putbuf(buffer,size);
    return size;
  }
  else if (fd > 1) 
	{
  	if(theFile==NULL) return -1;
    return file_write(theFile, buffer, size);
  }
  return -1;
}

void seek(int fd, unsigned position) {
}

unsigned tell (int fd) {
}

void close (int fd) {
}

void check_ptr(void* esp) {
	/*
  if(ptr == NULL)
    return false;
  if(!is_user_vaddr(ptr))
    return false;*/
  if (!is_user_vaddr(esp) || esp < USER_BOTTOM){
    sys_exit(-1);
  } else {
    if(pagedir_get_page(thread_current()->pagedir, esp) == NULL){
      sys_exit(-1);
    }
  }
}

void sys_exit (int status) {
	struct thread* cur = thread_current();
	if (status < -1) {
		status = -1;
	}
	printf("%s: exit(%d)\n",cur->name,status);
	thread_exit();
}

void
syscall_init (void) 
{
	list_init(&list_fds);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f) 
{
  /*if(check_ptr(f->esp)) {
    thread_exit();
  }*/
	check_ptr(f->esp);
	check_ptr(f->esp+1);
	check_ptr(f->esp+2);
	check_ptr(f->esp+3);

  int code = *(int*)f->esp;
  int* esp = (int*)f->esp;
  switch(code) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT: {
      int status = *(esp + 1);
      //exit(status);
			sys_exit(status);
      break;
  	}
  	case SYS_EXEC: {
    	break;
  	}
  	case SYS_WAIT: {
    	break;
  	}
  	case SYS_CREATE: {
    	break;
  	}
  	case SYS_REMOVE: {
    	break;
  	}
  	case SYS_OPEN: {
    	break;
  	}
  	case SYS_FILESIZE: {
    	break;
  	}
  	case SYS_READ: {
    	break;
  	}
  	case SYS_WRITE: {
			int fd = *((int*)f->esp + 1);
			const void* buffer = (const void*)(*((int*)f->esp + 2));
			unsigned size = *((unsigned*)f->esp + 3);
			check_ptr(buffer);
			f->eax = write(fd, buffer, size);
    	break;
  	}
  	case SYS_SEEK: {
    	break;
  	}
  	case SYS_TELL: {
    	break;
  	}
  	case SYS_CLOSE: {
    	break;
  	}
  };
  //printf ("system call!\n");

  //thread_exit ();
}
