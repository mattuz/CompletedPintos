#include "userprog/syscall.h"
#include <stdio.h>
#include <stdbool.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"


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
  
  valid_buff(f->esp, 4);
  
  int syscall_num = *(int*)(f->esp);
  //void *buffer;

  //const char *file;
  //int fd;
  //unsigned size;
  
  switch(syscall_num) {
  case SYS_HALT: ;
    halt();
    break;

  case SYS_EXIT: {
    valid_buff(f->esp+4, 4);
    void *arg1 = f->esp+4;
    int status = *(int*)arg1;
    exit(status);
    break;
  }
    

  case SYS_EXEC: {

    valid_buff(f->esp+4, 4);
    void *arg1 = f->esp+4;
   
    
    //printf("syscall exec\n");

    char *cmd_line = *(const char **)arg1;
    valid_str(cmd_line);
    f->eax = exec(cmd_line);
    break;
  }
    

  case SYS_WAIT: {
    valid_buff(f->esp+4, 4);
    void *arg1 = f->esp+4;
  
    tid_t child_tid = *(tid_t *)arg1;
    f->eax = wait(child_tid);
    break;
  }
    

  case SYS_CREATE: {
    valid_buff(f->esp+4, 4);
    valid_buff(f->esp+8, 4);
    void *arg1 = f->esp+4;
    void *arg2 = f->esp+8;
   
    
  
    const char *file = *(const char **)arg1;
    unsigned initial_size_create = *(unsigned*)arg2;
    valid_str(file);
    f->eax = create(file, initial_size_create);
    break;
  }
    

  case SYS_REMOVE: {
    valid_buff(f->esp+4, 4);
    void *arg1 = f->esp+4;  
 
    const char *file_name = *(const char**)arg1;
    valid_str(file_name);
    f->eax = remove(file_name);
    break;
  }
    

  case SYS_OPEN: {
    valid_buff(f->esp+4, 4);
    void *arg1 = f->esp+4; 
  
    const char *file = *(const char**)arg1;
    valid_str(file);
    f->eax = open(file);
    break;
  }
    

  case SYS_FILESIZE: {
    valid_buff(f->esp+4, 4);
    void *arg1 = f->esp+4;
 
    int fd = *(int*)arg1;
    valid_fd(fd);
    f->eax = file_size(fd);
    break;
  }
    

  case SYS_READ: {
    valid_buff(f->esp+4, 4);
    valid_buff(f->esp+8, 4);
    valid_buff(f->esp+12, 4);
    void *arg1 = f->esp+4;
    void *arg2 = f->esp+8;
    void *arg3 = f->esp+12;  

    int fd = *(int*)arg1;
    void *buffer = *(void**)arg2; 
    unsigned size = *(unsigned*)arg3;
    valid_fd(fd);
    valid_buff(buffer, size);
  
    f->eax = read(fd, buffer, size);
    break;
  }
    

  case SYS_WRITE: {
    valid_buff(f->esp+4, 4);
    valid_buff(f->esp+8, 4);
    valid_buff(f->esp+12, 4);
    void *arg1 = f->esp+4;
    void *arg2 = f->esp+8;
    void *arg3 = f->esp+12;  

    int fd = *(int*)arg1;
    void *buffer = *(char**)arg2;
    unsigned size = *(unsigned*)arg3;
    valid_fd(fd);
    valid_buff(buffer, size);
    f->eax = write(fd, buffer, size);
    break;
  }
    

  case SYS_SEEK: {
    valid_buff(f->esp+4, 4);
    valid_buff(f->esp+8, 4);

    void *arg1 = f->esp+4;
    void *arg2 = f->esp+8;
  
  
    int fd = *(int*)arg1;
    unsigned position = *(unsigned*)arg2; 
    valid_fd(fd);
    seek(fd, position);
    break;
  }
    

  case SYS_TELL: {
    valid_buff(f->esp+4,4);
    void *arg1 = f->esp+4; 
  
    int fd = *(int*)arg1;
    valid_fd(fd);
    f->eax = tell(fd);
    break;

  }
    

  case SYS_CLOSE: {
    valid_buff(f->esp+4, 4);
    void *arg1 = f->esp+4; 
  
    int fd= *(int*)arg1;
    valid_fd(fd);
    close(fd);
    break;
  }
    

  default:; //Syscall finns inte
    exit(-1);
  }
}


void halt(void){
  shutdown_power_off();
}


void exit (int status){  
  if(thread_current()->pc_parent != NULL){
    thread_current()->pc_parent->exit_status = status; //skulle detta skyddas av semaphor?
  } 
  thread_exit();
}


tid_t exec (const char *cmd_line){
  tid_t tid = process_execute(cmd_line);
  return tid;
}


bool create (const char *file, unsigned initial_size){
  return filesys_create(file, initial_size);
}


bool remove(const char *file_name){
  return filesys_remove(file_name);
}


int open (const char *file){
  struct thread *current_thread = thread_current();
  struct file *my_file = filesys_open(file);
  if(my_file == NULL){
    return -1;
  }
  for(int i = 2; i<130; i++){
    if (current_thread->files[i] == NULL){
      current_thread->files[i] = my_file;
      return i;
    }
  }
 
  return -1;
}


int file_size(int fd){
  struct thread *thread = thread_current();
  if (thread->files[fd] == NULL) {
    return -1;
  }
  return file_length(thread->files[fd]);
}


int read (int fd, void *buffer, unsigned size){
  struct thread *thread = thread_current();
  int bytes_read = 0;
  if (fd == 0){
    for(unsigned i = 0; i < size; i++) {
      *((char *)buffer) = input_getc();
      buffer += sizeof(char);
      bytes_read += sizeof(char);
      }
      return bytes_read;
  }
  else if (fd == 1){
    return -1;
  }
  else {
    if(thread->files[fd] == NULL){ //Filen existerar inte
      return -1;
    }
    return (int) file_read(thread->files[fd], buffer, size);
  }
}


int write (int fd, const void *buffer, unsigned size){
  struct file *file = thread_current()->files[fd];
  int written = 0;
  //if(fd == 1){
  if(fd == STDOUT_FILENO){
    putbuf(buffer, size);
    return size;
  }
  else if(fd > 129 || fd < 2){
    return -1;
  }
  else if(file == NULL){
    return -1;
    
  } else {
    written = file_write(file, buffer, size); 
  }
  return written;
}


void seek(int fd, unsigned position){
  //set cur pos i open file till position. Om större än fil, sätt end of file. 
  struct thread *current_thread = thread_current();
  if (current_thread->files[fd] == NULL) {
    return -1;
  }
  if(position > file_length(current_thread->files[fd])){
    file_seek(current_thread->files[fd], file_size(current_thread->files[fd]));    
  } else {
    file_seek(current_thread->files[fd], position);
  }
}


unsigned tell(int fd){
  struct thread *current_thread = thread_current();
  if (current_thread->files[fd] == NULL) {
    return -1;
  }
  return file_tell(current_thread->files[fd]);
}


void close (int fd){
  struct thread *current_thread = thread_current(); 
  file_close(current_thread->files[fd]);
  current_thread->files[fd] = NULL;
}


int wait (tid_t child_tid){ //returns exit status
  return process_wait(child_tid);
}


void valid_buff(const void *buffer, unsigned size){
  
  if (buffer == NULL){
    exit(-1);
  }
  valid_addr(buffer);
  valid_addr(buffer + size - 1);

  //int pgs = size/4096

  for (unsigned i = 0; i < size; i+=4096) {
    if(i%4096 == 0) {
      valid_addr(buffer+i);
    }
  }
    

  /**unsigned num_ptr = 0;
  while(num_ptr != size){
    valid_addr((void*)&buffer[num_ptr]);
    num_ptr++;
  }*/

  //printf("%u\n",size/4096);
  /**int pg = 0;
  for(int i = 0; i < ((int)size / 4096); i++) {
   
    valid_addr((void*)&buffer[pg]);
    pg += 4096;

  }**/
  //valid_addr((void*)&buffer[size]);



}


void valid_addr (const void *ptr){ 
  if(ptr == NULL || !is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, ptr) == NULL) {
    exit(-1);
  }
}


void valid_fd (int fd){
  if (fd < 0 || fd > 129){
    exit(-1);
  }
}


void valid_str (const char *string){
  int i = 0;
  if (string == NULL) {
    exit(-1);
  }
  do {
    valid_addr((void*)&(string[i]));
    i++;
  }
  while(string[i] != '\0');
}


//ÖVERFLÖDIG?
int convert_to_kernel_pointer(const void *pointer){
  void *ptr=pagedir_get_page(thread_current()->pagedir, pointer);
  if (!ptr){
    exit(-1);
  } else return (int)ptr;
}
