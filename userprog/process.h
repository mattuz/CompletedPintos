#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name); //file_name är numera cmd_line
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct aux { //LIMA HÄRIFRÅN
    char *file_name;
    struct parent_child *parent_child;
    //"vad som mer kan behövas"
};
#endif /* userprog/process.h */
