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


static void syscall_handler (struct intr_frame *);
     
static struct file_descriptor
{
  int fd_id;
  char* name;
  struct thread* owner;
  struct file* ptr;
  struct list_elem elem; 
};

void halt (void) 
{
  shutdown_power_off();
}

pid_t exec (const char *cmd_line) 
{
	// printf("\n\nVALOR INICIAL : %s\n\n", cmd_line);
  //acquire_filesys_lock();
  int i = 0;
  int tam = 0;
  while (cmd_line[i] != '\0')
	{
    tam++;
    i++;
  }
  char cmd_cp[tam+1];
  char cmd_cp1[tam+1];
	// for(int i = 0;i<tam;i++){
    //  cmd_cp[i] = cmd_line[i];  
  // }
  cmd_cp[tam] = '\0';
  cmd_cp1[tam] = '\0';

  char* auxTok, *save_ptr;
  strlcpy(cmd_cp, cmd_line, tam+1);
  strlcpy(cmd_cp1, cmd_line, tam+1);
  auxTok = strtok_r(cmd_cp, " ", &save_ptr);
  struct file* file_opened = filesys_open (auxTok);
	//printf("\n\nVIZCARRAAAAAAA\n\n");
  if (file_opened == NULL)
  {
		//release_filesys_lock();
		return -1;
  }
  else
	{
		file_close(file_opened);
		//release_filesys_lock();
		// printf("\n\nVALOR FINAL : %s\n\n", cmd_cp);
		auto fff = process_execute(cmd_cp1);
		//printf("\n\n%d\n\n", fff);
		return fff;
	}
}

int wait (pid_t pid) 
{
  // intr_disable ();
  tid_t id = process_wait(pid);
  thread_current()->final_status = -1;
  return id;
}

bool create (const char *file_name, unsigned initial_size) 
{
  return filesys_create(file_name,initial_size);
}

bool remove (const char *file) 
{
  return filesys_remove(file);
}

bool check_write(struct thread* t, char* name) {
  if(strcmp(t->name, name) == 0) {
    return false;
  }
  if(t->parent) {
    return true && check_write(t->parent, name);
  } else {
    return true;
  }
}

int open (const char *file)
{
  int i = 0;
  int tam = 0;
  while (file[i] != '\0')
	{
    tam++;
    i++;
  }
  char f_cp[tam+1];
  strlcpy(f_cp, file, tam+1);
  // printf("AAA: %s\n", f_cp);
  get_syslock();
	struct file* archivo =  filesys_open (file);
  release_syslock();
  if(!check_write(thread_current(), f_cp)) {
    file_deny_write(archivo);
  }
	if(archivo == NULL) 
	{
		return -1;
	} else 
	{
		struct file_descriptor* filed = palloc_get_page(0);
		struct thread *t_cur = thread_current ();
		filed->ptr = archivo;
		filed->fd_id = ++t_cur->fd;
		filed->owner = t_cur;
    filed->name = f_cp;
		list_push_back (&(t_cur->f_opened), &filed->elem);
		return t_cur->fd;
  }
}

int filesize (int fd) {
  struct file* theFile = NULL;
	// theFile = palloc_get_page(0);

  struct file_descriptor *fdesc = NULL;
  struct thread* t_cur = thread_current();
  struct list_elem *e;

  for(e = list_begin(&t_cur->f_opened); e != list_end(&t_cur->f_opened); e = list_next(e)) {
    struct file_descriptor *f = list_entry(e, struct file_descriptor, elem);
    if(fd == f->fd_id) {
      fdesc = f;
      break;
    }
  }

  if(fdesc != NULL)
    theFile = fdesc->ptr;

  if (fd > 1) {
  	if(theFile==NULL) 
		{
			return -1;
		}
    else {
      get_syslock();
      auto temp = file_length(theFile);
      release_syslock();
      return temp;
    }
  }
}

int read (int fd, void *buffer, unsigned size) 
{
  if (fd == 0) 
	{    
    return (int)input_getc();
  }
  if (fd == 1 || list_empty(&thread_current()->f_opened)) 
	{
    return 0;
  }
  struct file* theFile = NULL;
	// theFile = palloc_get_page(0);
  
  struct file_descriptor *fdesc = NULL;
	// fdesc = palloc_get_page(0);
  struct thread* t_cur = thread_current();
  struct list_elem *e;
  for(e = list_begin(&t_cur->f_opened); e != list_end(&t_cur->f_opened); e = list_next(e)) {
    struct file_descriptor *f = list_entry(e, struct file_descriptor, elem);
    if(fd == f->fd_id) {
      fdesc = f;
      break;
    }
  }
  if(fdesc != NULL)
    theFile = fdesc->ptr;

 // if (fd > 1) 
//	{
	if(theFile==NULL) 
	{
		return -1;
	}
	else 
	{
		return file_read(theFile, buffer, size);
	}
  return -1;
}

int write (int pos, const void *buffer, unsigned size) 
{
	//check_ptr(buffer);
  //struct list_elem* iter = list_begin(&list_fds);
  struct file* theFile = NULL;
	// theFile = palloc_get_page(0);

  struct file_descriptor *fdesc = NULL;
	fdesc = palloc_get_page(0);
  struct thread* t_cur = thread_current();
 	//t_cur->f_opened
  struct list_elem *e;
  for(e = list_begin(&t_cur->f_opened); e != list_end(&t_cur->f_opened); 
			e = list_next(e)) 
	{
    struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
    if(pos == f->fd_id) 
		{
      fdesc = f;
      break;
    }
  }

  if(fdesc != NULL)
    theFile = fdesc->ptr;
  
  if (pos == 1) 
	{
    putbuf(buffer,size);
    return size;
  }

  else if (pos > 1) 
	{
  	if(theFile == NULL) 
		{
			return -1;
		}
    else 
		{
      // printf("TNAME: %s\n", thread_current()->name);
      // printf("NAME: %s\n", fdesc->name);
      get_syslock();
      auto temp = file_write(theFile, buffer, size);
      release_syslock();
      return temp;
    } 
  }
  return -1;
}

void seek (int pos, unsigned position) {
  struct file* theFile = NULL;
	// theFile = palloc_get_page(0);

  struct file_descriptor *fdesc = NULL;
	// fdesc = palloc_get_page(0);
  struct thread* t_cur = thread_current();
 	//t_cur->f_opened
  struct list_elem *e;
  for(e = list_begin(&t_cur->f_opened); e != list_end(&t_cur->f_opened); 
			e = list_next(e)) 
	{
    struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
    if(pos == f->fd_id) 
		{
      fdesc = f;
      break;
    }
  }

  if(fdesc != NULL)
    theFile = fdesc->ptr;
  
  if(theFile)
    file_seek(theFile, position);
}

unsigned tell (int pos) 
{
  struct file* theFile = NULL;
	// theFile = palloc_get_page(0);

  struct file_descriptor *fdesc = NULL;
	// fdesc = palloc_get_page(0);
  struct thread* t_cur = thread_current();
 	//t_cur->f_opened
  struct list_elem *e;
  for(e = list_begin(&t_cur->f_opened); e != list_end(&t_cur->f_opened); 
			e = list_next(e)) 
	{
    struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
    if(pos == f->fd_id) 
		{
      fdesc = f;
      break;
    }
  }

  if(fdesc != NULL)
    theFile = fdesc->ptr;
  
  if(theFile)
    return file_tell(theFile);
  return -1;
}

void close (int pos) 
{
  if (pos == 1) 
	{
    sys_exit (-1);
  }
  struct thread* t_cur = thread_current();
  struct list_elem *e;
  struct file* theFile = NULL;
  struct file_descriptor *fdesc = NULL;

	// fdesc = palloc_get_page(0);
	// theFile = palloc_get_page(0);

  for (e = list_begin(&t_cur->f_opened); e != list_end(&t_cur->f_opened); 
			e = list_next(e)) 
	{
    struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
    if (pos == f->fd_id) 
		{
      fdesc = f;
      break;
    }
  }
  // printf("AAAAAAAA\n");

  if (fdesc != NULL)
    theFile = fdesc->ptr;

  if (theFile) 
	{
    get_syslock();
    file_close(theFile);
    list_remove(&fdesc->elem);
    release_syslock();
  }
}

//funcion para verifiacar si el puntero es válido y no referencia a posiciones fuera del contexto de usuario y si está previamente mapeado
void check_ptr(void* pos) 
{
  if (!is_user_vaddr(pos) || pos < USER_BOTTOM)
	{
    sys_exit(-1);
  } 
	else 
	{
    // printf("GA\n");
    if( pagedir_get_page(thread_current()->pagedir, pos) == NULL)
		{
      sys_exit(-1);
    }
  }
}

void sys_exit (int status) 
{
	if (status < -1) 
	{
		status = -1;
	}
  thread_current()->final_status = status;
  //if(thread_current()->parent) {
  //  thread_current()->parent->final_status = status;
  //}
 	printf("%s: exit(%d)\n",thread_current()->name,thread_current()->final_status);
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
	check_ptr(f->esp);
	check_ptr(f->esp+1);
	check_ptr(f->esp+2);
	check_ptr(f->esp+3);

  int code = *(int*)f->esp;
  int* esp = (int*)f->esp;
  switch(code) 
	{


		case SYS_WAIT: 
		{
      check_ptr((esp+1));
  		f->eax = wait(*(esp+1));
    	break;
  	}


    case SYS_HALT: 
		{
			halt();
			break;
		}
    
		
		case SYS_EXIT: 
		{
    	int status = *(esp + 1);
			sys_exit(status);
    	break;
  	}


  	case SYS_EXEC: 
		{
			check_ptr(esp+1);
      check_ptr(esp+2);
      // printf("OWO\n");
      // printf("GA: %c\n", **(char**)(esp+1));
      // printf("OWO\n");
			check_ptr(*(esp+1));
      // check_ptr(*(esp+2));
      // check_ptr(*(esp+4));
      const char *cmd_line = *(char**)(esp+1);
      for(int i = 0; cmd_line[i] != '\0';) {
        i++;
        // printf("GA: %c\n", cmd_line[i]);
        // printf("AA: %d\n", i);
        check_ptr(esp + i + 1);
        check_ptr(cmd_line + i);
        // printf("OWO\n");
      }
			// check_ptr(cmd_line);
			f->eax = exec(cmd_line);
    	break;
  	}


  	case SYS_CREATE: 
		{
		  check_ptr(esp+2);
			unsigned size = *(int*)(esp+2);
   	  const char * name = *(char**)(esp+1);
			check_ptr(name);
      get_syslock();
      f->eax = filesys_create(name, size);
      release_syslock();
    	break;
    }


  	case SYS_REMOVE: 
		{
      check_ptr(esp+1);
      get_syslock();
      f->eax = filesys_remove((const char*)*(esp+1));
      release_syslock();
    	break;
  	}


  	case SYS_OPEN: 
		{
      
      char * f_name = *(char **)((int*)esp+1);
      
      check_ptr(esp+1);
      check_ptr(*(esp+1));
      f->eax = open(f_name);
    	break;
  	}


  	case SYS_CLOSE: 
		{ 
			esp++;
			int fd = *((int*)esp);
			check_ptr(*(esp + 1));
			close(fd);
      //check_ptr((esp+1));
      //check_ptr(*(esp+1));
      close(*(esp+1));
    	break;
  	}


  	case SYS_FILESIZE: 
		{
      esp++;
			int fd = *((int*)esp);
      f->eax = filesize(fd);
    	break;
  	}


  	case SYS_READ: 
		{
      int fd = *((int*)f->esp + 1);
      // printf("\nAAAAAA\n");
			const void* buffer = (const void*)(*((int*)f->esp + 2));
      // printf("AAAAAA\n");
			unsigned size = *((unsigned*)f->esp + 3);
      // printf("AAAAAA\n");
			check_ptr(buffer);
			f->eax = read(fd, buffer, size);
      break;
  	}


  	case SYS_WRITE: 
		{
     	esp++;
			int fd = *((int*)esp);
			const char* buffer = (const char*)*(esp + 1);
			unsigned size = *((unsigned*)esp + 2);
			check_ptr(*(esp + 1));
			check_ptr(esp + 3);
			check_ptr(buffer);
			f->eax = write(fd, buffer, size);
    	break;
  	}


  	case SYS_SEEK: 
		{
      // printf("uWU\n");
			esp++;
			int fd = *((int*)esp);
      int num = *((int*)esp+1);
      // printf("fd: %d\n", num);
			check_ptr(esp);
      check_ptr(esp+1);
      // printf("\n\nSEEK\n\n");
      // sys_exit(-1);
			seek(fd, num);
    	break;
  	}


  	case SYS_TELL: 
		{
      esp++;
			int fd = *((int*)esp);
      check_ptr(esp);
      f->eax = tell(fd);
    	break;
  	}


  };


}