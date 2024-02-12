#include "userprog/syscall.h"
#include <stdio.h>
#include <stdbool.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"




bool create (const char *file, unsigned initial_size);
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  int *stack_pointer = (int*) f->esp;
  if(!valid_addr(stack_pointer)){
    exit(-1);
  }
  if(!valid_addr(stack_pointer + 4)){
    exit(-1);
  }
  if(!valid_addr(stack_pointer + 8)){
    exit(-1);
  }
  if(!valid_addr(stack_pointer + 12)){
    exit(-1);
  }
  
  switch(*stack_pointer) {
  case 0:
    halt();
    break;
  case 1: ;
    if(!valid_addr(f->esp + 4)){
      exit(-1);
    }
    int status = *(int*)(f->esp + 4);
    exit(status);
    break;
  case 2: ;
    if(!valid_addr(f->esp + 4)){
        exit(-1);
      }
    char *cmd_line = *(char **)(f->esp + 4);
    f->eax = exec(cmd_line);
    break;
  case 3: ;
    if(!valid_addr(f->esp + 4)){
        exit(-1);
      }
    tid_t *child_tid = (tid_t **)(f->esp + 4);
    f->eax = wait(child_tid);
    break;
  case 4: ;
    if(!valid_addr(f->esp + 4)){
        exit(-1);
      }
    char *file_create = *(char **)(f->esp + 4);
    if(!valid_addr(f->esp + 8)){
      exit(-1);
    }
    unsigned initial_size_create = *(unsigned*)(f->esp + 8);
    //int file_create = convert_to_kernel_pointer((f->esp + 4));
    f->eax = create(file_create, initial_size_create);
    break;
  case 5: ;
    //REMOVE
    break;
  case 6: ;
    if(!valid_addr(f->esp + 4)){
      exit(-1);
    }
    char *file_open = *(char**) (f->esp + 4);
    f->eax = open(file_open);
    break;
  case 7: ;
    //FILESIZE
    break;
  case 8: ;
    if(!valid_addr(f->esp + 4)){
      exit(-1);
    }
    int fd_read = *(int*) (f->esp + 4);
    if(!valid_addr(f->esp + 8)){
      exit(-1);
    }
    void *buffer_read = *(void**)(f->esp + 8);
    if(!valid_addr(f->esp + 12)){
      exit(-1);
    }
    unsigned size_read = *(unsigned*) (f->esp + 12);
    f->eax = read(fd_read, buffer_read, size_read);
    break;
  case 9: ;
    if(!valid_addr(f->esp + 4)){
        exit(-1);
      }
    int fd_write = *(int*) (f->esp + 4);
    if(!valid_addr(f->esp + 8)){
      exit(-1);
    }
    void *buffer_write = *(void**)(f->esp + 8);
    if(!valid_addr(f->esp + 12)){
      exit(-1);
    }
    unsigned length_write = *(unsigned*) (f->esp + 12);
    f->eax = write(fd_write, buffer_write, length_write);
    break;
  case 10: ;
    //SEEK
    break;
  case 11: ;
    //TELL
    break;
  case 12: ;
    if(!valid_addr(f->esp + 4)){
      exit(-1);
    }
    int fd_close = *(int*) (f->esp + 4);
    close(fd_close);
    break;
  }

  //thread_exit ();
}


int convert_to_kernel_pointer(const void *pointer){
  void *ptr=pagedir_get_page(thread_current()->pagedir, pointer);
  if (!ptr){
    exit(-1);
  } else return (int)ptr;
}

void halt(void){
  shutdown_power_off();
}

bool create (const char *file, unsigned initial_size){
  //validate input
  if(!valid_str(file)){
    exit(-1);
  }
  return filesys_create(file, initial_size);
}

int open (const char *file){
  //validate input
  if(!valid_str(file)){
    exit(-1);
  }

  struct thread *current_thread = thread_current();
  struct file *my_file = filesys_open(file);
  if (my_file == NULL){
    return -1;
  }
  else {
    int fd = fd_handler(current_thread);

    if (fd == NULL){
      return -1;
    }
    else {
      current_thread->files[fd] = my_file;
      return fd;
    }
  }
  return -1;
}

void close (int fd){
   if(fd < 130 && fd > 1 ){
    struct thread *current_thread = thread_current();
    if(current_thread->files[fd] != NULL){
      file_close(current_thread->files[fd]);
      current_thread->taken_fds[fd] = NULL;
      current_thread->files[fd] = NULL;
    }
  }
  else return -1;
}

int read (int fd, void *buffer, unsigned size){
  valid_fd(fd);
  if (!valid_addr(buffer)){
    exit(-1);
  }
  struct thread *thread = thread_current();

  if (fd == 0){
    int bytes_read = 0;
    for(unsigned int i = 0; i < size; i++) {
      *(char*)buffer = input_getc();
      buffer += sizeof(char);
      if (!valid_addr(buffer)){
        exit(-1);
      }
      bytes_read += sizeof(char);
    }
    return bytes_read;
  }
  
  else if(thread->files[fd]!= NULL){
    if((fd < 130) && (fd > 1)){
      struct file *file = thread-> files[fd];

      return file_read(file, buffer, size);;
    }
  }
  else {
    //return -1;
    exit(-1);
  }
}

int write (int fd, const void *buffer, unsigned size){// denna kanske ska validateas mer (hela size)
  //validate input
  valid_fd(fd);

  if (!valid_addr(buffer)){
    exit(-1);
  }

  struct thread *thread = thread_current();
  struct file *file = thread-> files[fd];

  if(fd < 0 || fd > 129){
    return -1;
  }
  else if (fd == 1){

    putbuf((char*)buffer, (size_t)size);
    return size;

  }
  else if(fd < 130 && fd > 1){
    return file_write(file, buffer, size);
  } else {
    return -1;}
}

void exit (int status){  
  struct thread *thread = thread_current();
  if(thread->parent != NULL){
    thread->parent->exit_status = status; //skulle detta skyddas av semaphor?
  thread_exit();
  }
  
}

int fd_handler (struct thread *thread){
  int possible_fd = 2;
  while (possible_fd < 130){
    if (thread->taken_fds[possible_fd] == possible_fd){
      possible_fd++;
    } else {
      thread->taken_fds[possible_fd] = possible_fd;
      return possible_fd;
    }
  }
  return NULL;
}

tid_t exec (const char *cmd_line){
  //validate input
  if(!valid_str(cmd_line)){
    exit(-1);
  }

  tid_t tid = process_execute(cmd_line);
  if (tid == TID_ERROR) {
    return -1;
  } else {
    return tid;
  }
}

//Should wait until a given child has exitecall.c:172:14: error: expected ‘;’ before numeric constant
int wait (tid_t child_tid){ //returns exit status
  return process_wait(child_tid);
}

//Kan optimeras till en rad <3
bool valid_addr (void *ptr){ //skrev void så länge, vet inte om det alltid kommer vara samma slags pointer
  if (is_user_vaddr(ptr) 
  && (pagedir_get_page(thread_current()->pagedir,ptr)!=NULL) 
  && ptr != NULL){
    return true;
  }
  return false;
}

void valid_fd (int fd){
  if (fd < 0 || fd > 129){
    exit(-1);
  }
}

bool valid_str (const char *string){
  if (string == NULL) { //Om det inte ens pekar på en string
    return false;
  }
  
  //for(int i = 0; i<strlen(string); i++)
  int i = 0;
  while (true){
    if (!valid_addr(&string[i])) { //om det är något whack. 
      return false;
    } 
    if (string[i]=='\0'){ //oklart om man kan jämföra såhär, måste nog castastring eller nåt
      return true;
    }
    i++;
  }
}

