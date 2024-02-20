#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"

static thread_func start_process NO_RETURN;
static bool load(const char* cmd_line, void (**eip)(void), void **esp);
static void dump_stack(const void* esp);

struct aux { //LIMA HÄRIFRÅN
    char *cmd_line;
	struct thread *t_parent; 
    //struct parent_child *parent_child;
};

/* Starts a new thread running a user program loaded from
	CMD_LINE.  The new thread may be scheduled (and may even exit)
	before process_execute() returns.  Returns the new process's
	thread id, or TID_ERROR if the thread cannot be created. */
//tid_t process_execute(const char* cmd_line)
tid_t process_execute(const char *cmd_line)

{//LISMA
  //Här är vi inne i föräldern

  struct thread *t_cur = thread_current();
  sema_init(&(t_cur->pc_sema), 0);

  /* Make a copy of FILE_NAME. //CMD_LINE NUMERA
     Otherwise there's a race between the caller and load(). */
  char *cl_copy = palloc_get_page (0);
  if (cl_copy == NULL) //cl_copy numera!!
    return TID_ERROR;
  strlcpy (cl_copy, cmd_line, PGSIZE); //cl_copy

  char *file_name = palloc_get_page (0);

/*Läs av file name från cmd_line, avsluta med NULL*/
  if(file_name == NULL){
	return TID_ERROR;
  }
  int num_chars = 0;
  char char_cur = cmd_line[0];
  int max = 100; 
  while(char_cur != ' '){
	max--;
	if (max == 0){
		break; //saknar null terminator
	}
	file_name[num_chars] = char_cur;
	num_chars++;
	char_cur = cmd_line[num_chars];
  }
  file_name[num_chars] = NULL;
  
  struct aux *args = (struct aux *)malloc(sizeof(struct aux));
  args->cmd_line = cl_copy;
  args->t_parent = t_cur;

  tid_t tid_c = thread_create (file_name, PRI_DEFAULT, start_process, args); //thread_create(cmd_line, PRI_DEFAULT, start_process, cl_copy);
  sema_down(&(t_cur->pc_sema));
  free(args);
  palloc_free_page(file_name);

  if (tid_c == TID_ERROR){
    palloc_free_page (cl_copy);
	} 
	
	// Tilldela barnet till pc mapping och se efter att det laddat successfully
	struct list_elem *elem;
	for(elem = list_begin (&t_cur->children_list); elem != list_end (&t_cur->children_list); elem = list_next (elem)){
		struct parent_child *pc_child = list_entry(elem, struct parent_child, child); 
		if(pc_child->child_tid == NULL){ //pc_child är barnet som just skapats
			pc_child->child_tid = tid_c;
			if(pc_child->load){
				return tid_c;
			}
			else {
				return TID_ERROR;
			}
		}
	}
	return TID_ERROR;

}//LISMA

/* A thread function that loads a user process and starts it
	running. */
static void start_process(void *args) //LISMA
{									//aux är numera cmd_line_
	//char* cmd_line = cmd_line_; detta är nytt

	//Här inne är vi inne i barnet
	struct thread *t_cur = thread_current(); //Ny process
	struct thread *t_parent = ((struct aux *)args)-> t_parent;
	struct intr_frame if_;
	char *cmd_line = ((struct aux *)args)->cmd_line;
	

	// Strukturera parent_child mapping
	struct parent_child *parent_child = malloc(sizeof(struct parent_child));
	sema_init(&parent_child->wait_sema, 0);
	
	t_cur->parent = parent_child;
	parent_child->exit_status = 0;
	parent_child->alive_count = 2;
	parent_child-> child_tid = NULL; // Sätt i process_execute()

	lock_init(&parent_child->alive_lock);
	list_init(&(t_cur->children_list));
	list_push_back(&(t_parent->children_list), &(parent_child->child));
	

	/* Initialize interrupt frame and load executable. */
	memset(&if_, 0, sizeof if_);
	if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
	if_.cs = SEL_UCSEG;
	if_.eflags = FLAG_IF | FLAG_MBS;
	parent_child->load = load(cmd_line, &if_.eip, &if_.esp);



	/* If load failed, quit. */
	palloc_free_page (cmd_line); //här står det cmd_line ist för aux-file_name

	if (!parent_child->load) {
		sema_up(&(((struct thread *)t_parent)->pc_sema)); 

		thread_exit ();
	} //LISMA
	sema_up(&(((struct thread *)t_parent)->pc_sema)); 

	/* Start the user process by simulating a return from an
		interrupt, implemented by intr_exit (in
		threads/intr-stubs.S).  Because intr_exit takes all of its
		arguments on the stack in the form of a `struct intr_frame',
		we just point the stack pointer (%esp) to our stack frame
		and jump to it. */
	asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
	NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
	it was terminated by the kernel (i.e. killed due to an
	exception), returns -1.  If TID is invalid or if it was not a
	child of the calling process, or if process_wait() has already
	been successfully called for the given TID, returns -1
	immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) //LISMA
{
  //while(true){};
  struct thread *t_cur = thread_current ();  
  struct list_elem *elem;
  int exit_status;
  struct parent_child *pc_child = NULL;

  for(elem = list_begin (&t_cur->children_list); elem != list_end (&t_cur->children_list);
           elem = list_next (elem)) {
		


	struct parent_child *child_it = list_entry (elem, struct parent_child, child);
    if (child_it->child_tid == child_tid){
		pc_child = child_it; //Child hittad
		break;
	}
  }
  if (pc_child != NULL){
	sema_down(&pc_child->wait_sema);
	exit_status = pc_child->exit_status;
	list_remove(elem);
	free(pc_child);
	pc_child = NULL;
	return exit_status;
  }
  return -1;

}//LISMA

/* Free the current process's resources. */
void process_exit(void) //LISMA
{
  struct thread *t_cur = thread_current ();
  uint32_t *pd;

  if (t_cur->parent != NULL) { 
    lock_acquire(&t_cur->parent->alive_lock); //Kolla om parent är null. sätt parent null i init_thread
    (t_cur->parent->alive_count)--;
	if (t_cur->parent->alive_count == 0){ //Parent har väntat färdigt på child (t_cur)
		free(t_cur->parent);
		t_cur->parent = NULL;
	}
	else { //Child (t_cur) exit före paremt och måste vänta
		sema_up(&t_cur->parent->wait_sema);
		lock_release(&t_cur->parent->alive_lock);
	}
  }

//har några barn exitat
  while(!list_empty(&(t_cur->children_list))){
	struct list_elem *elem = list_pop_front(&(t_cur->children_list));
	struct parent_child *pc_child = list_entry(elem, struct parent_child, child);
	lock_acquire(&pc_child->alive_lock);
	(pc_child->alive_count)--;
	if(pc_child->alive_count == 0){ //Child har väntat färdigt på parent(t_cur)
		free(pc_child);
		pc_child = NULL;
	}
	else { //Parent (t_curr) exit före child och måste vänta
		lock_release(&pc_child->alive_lock);
	}
  }
  /* Destroy the current process's page directory and switch back
		to the kernel-only page directory. */
	pd = t_cur->pagedir;
	if (pd != NULL) {
		/* Correct ordering here is crucial.  We must set
			cur->pagedir to NULL before switching page directories,
			so that a timer interrupt can't switch back to the
			process page directory.  We must activate the base page
			directory before destroying the process's page
			directory, or our active page directory will be one
			that's been freed (and cleared). */
		t_cur->pagedir = NULL;
		pagedir_activate(NULL);
		pagedir_destroy(pd);
	}

	
}

/* Sets up the CPU for running user code in the current
	thread.
	This function is called on every context switch. */
void process_activate(void)
{
	struct thread* t = thread_current();

	/* Activate thread's page tables. */
	pagedir_activate(t->pagedir);

	/* Set thread's kernel stack for use in processing
		interrupts. */
	tss_update();
}

/* We load ELF binaries.  The following definitions are taken
	from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
	This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
	unsigned char e_ident[16];
	Elf32_Half e_type;
	Elf32_Half e_machine;	
	Elf32_Word e_version;
	Elf32_Addr e_entry;
	Elf32_Off e_phoff;
	Elf32_Off e_shoff;
	Elf32_Word e_flags;
	Elf32_Half e_ehsize;
	Elf32_Half e_phentsize;
	Elf32_Half e_phnum;
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
	There are e_phnum of these, starting at file offset e_phoff
	(see [ELF1] 1-6). */
struct Elf32_Phdr {
	Elf32_Word p_type;
	Elf32_Off p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf32_Word p_filesz;
	Elf32_Word p_memsz;
	Elf32_Word p_flags;
	Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(
	 struct file* file,
	 off_t ofs,
	 uint8_t* upage,
	 uint32_t read_bytes,
	 uint32_t zero_bytes,
	 bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *cmd_line, void (**eip) (void), void **esp) //cmd_line har bytt namn till file_name här
{
	struct thread* t = thread_current();
	struct Elf32_Ehdr ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;
	char file_copy;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

//LISMA FRAM TILL NÄSTA

  /* Set up stack. */
  if (!setup_stack (esp)){
    goto done;
  } //DENNA GÖRS NU LÄNGRE NER

  // arg null terminator. Ta bort null?
  *esp -= sizeof(NULL); // esp = stack pointer
  **((char** *)esp) = NULL;

  //Lägg args på stacken
  *esp -= strlen(cmd_line); //flytta stackpekare så att hela file_name får plats
  char* arg_ptr = memcpy(*esp, cmd_line, strlen(cmd_line)); // kopierar från file_name till esp
  
  //Beräkna argc
  int argc = 1; //varför? För att ett arg alltid är minst 1 lång.
  bool pre_space = false;
  for (int i = 0; cmd_line[i]; i++) { 
	if(cmd_line[i] == ' ') {
		if(pre_space) {
			pre_space = false;
			continue;
		}
		pre_space = true;
		argc++;
	}
	else{
		pre_space = false;
	}
  }

  //Gör stacken delbar med 4
  *esp -= (uintptr_t) *esp % 4;
  *esp -= sizeof(char*) * (argc+1);
  char **argv;
  argv = ((char **)*esp);


  //Lägg pekare till arg på stacken
  char *token;
  char *save_ptr;
  int arg_count = 0;
  for(token = strtok_r(arg_ptr, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
	argv[arg_count] = token;
	arg_count++;
  }
  argv[argc] = NULL;
  char *file_name = argv[0];

  //Lägg argv och argc på stacken
  *esp -= sizeof(argv);
  **((char** *)esp) = argv;
  *esp -= sizeof(argc);
  **((int**)esp) = argc;
  *esp -= sizeof(NULL);
  **((char** *)esp) = NULL;


   /* Uncomment the following line to print some debug
     information. This will be useful when you debug the program
     stack.*/
//#define STACK_DEBUG //komentera bort om vi inte vill ha debug info

#ifdef STACK_DEBUG
  printf("*esp is %p\nstack contents:\n", *esp);
  hex_dump((int)*esp , *esp, PHYS_BASE-*esp+16, true);
  /* The same information, only more verbose: */
  /* It prints every byte as if it was a char and every 32-bit aligned
     data as if it was a pointer. */
  void * ptr_save = PHYS_BASE;
  i=-15;
  while(ptr_save - i >= *esp) {
    char *whats_there = (char *)(ptr_save - i);
    // show the address ...
    printf("%x\t", (uint32_t)whats_there);
    // ... printable byte content ...
    if(*whats_there >= 32 && *whats_there < 127)
      printf("%c\t", *whats_there);
    else
      printf(" \t");
    // ... and 32-bit aligned content 
    if(i % 4 == 0) {
      uint32_t *wt_uint32 = (uint32_t *)(ptr_save - i);
      printf("%x\t", *wt_uint32);
      printf("\n-------");
      if(i != 0)
        printf("------------------------------------------------");
      else
        printf(" the border between KERNEL SPACE and USER SPACE ");
      printf("-------");
    }
    printf("\n");
    i++;
  }
#endif
//LISMA (tror debuggen inte finns kvar)

	/* Open executable file. */
	file = filesys_open(file_name);
	if (file == NULL) {
		printf("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr
		 || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2
		 || ehdr.e_machine != 3 || ehdr.e_version != 1
		 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
		printf("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Elf32_Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);

		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment(&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint32_t file_page = phdr.p_offset & ~PGMASK;
					uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint32_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
							Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes
							 = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
					}
					else {
						/* Entirely zero.
							Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment(
							  file,
							  file_page,
							  (void*) mem_page,
							  read_bytes,
							  zero_bytes,
							  writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* NY PLATS PÅ DENNA
	//Set up stack. 
	if (!setup_stack(esp))
		goto done;
	*/
	

	/* Start address. */
	*eip = (void (*)(void)) ehdr.e_entry;

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close(file);
	return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
	FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file)
{
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (Elf32_Off) file_length(file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
		user address space range. */
	if (!is_user_vaddr((void*) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void*) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
		address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
		Not only is it a bad idea to map page 0, but if we allowed
		it then user code that passed a null pointer to system calls
		could quite likely panic the kernel by way of null pointer
		assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
	UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
	memory are initialized, as follows:

		  - READ_BYTES bytes at UPAGE must be read from FILE
			 starting at offset OFS.

		  - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage, //uint32_t page_offset,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{ //LISMA page_offset är inte en grej här längre, kan vara så att vi implementerat detta.
  ASSERT ((/*page_offset +*/ read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);

  struct thread *t = thread_current();
  
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
	  //size_t page_read_bytes = page_offset + read_bytes;
	  size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
	  //NY OVAN, vår är den som står kvar
      //if (page_read_bytes > PGSIZE)
	    //   page_read_bytes = PGSIZE; //Detta fanns inte heller kvar. PROBELM?

      size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t* kpage = palloc_get_page(PAL_USER); //NY KPAGE
		if (kpage == NULL)
			return false;
	/*VÅR GAMLA KPAGE HÄR
	      // Get a page of memory. 
      bool new_kpage = false;
      uint8_t *kpage = pagedir_get_page (t->pagedir, upage);
      if (!kpage)
      {
            new_kpage = true;
            kpage = palloc_get_page (PAL_USER);
      }

      if (kpage == NULL)
        return false;
	
	*/

      /* Load this page. */ //LISMA page_offset
      if (file_read (file, kpage /*+ page_offset*/, page_read_bytes /*- page_offset*/) != (int) (page_read_bytes /*- page_offset*/))
      {
		palloc_free_page (kpage);
        return false;

      }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */       
      
		if (!install_page (upage, kpage, writable))
		{
				palloc_free_page (kpage);
				return false;
		}
      

      /* Advance. */
      read_bytes -= page_read_bytes /*- page_offset*/;
      zero_bytes -= page_zero_bytes;
      //page_offset = 0;		//LISMA
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
	user virtual memory. */
static bool setup_stack(void** esp)
{
	uint8_t* kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) 
		{
		success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
		if (success)
			*esp = PHYS_BASE; // ska vara -12 innan argumentpassing är implementerat
		else
			palloc_free_page (kpage);
		}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
	virtual address KPAGE to the page table.
	If WRITABLE is true, the user process may modify the page;
	otherwise, it is read-only.
	UPAGE must not already be mapped.
	KPAGE should probably be a page obtained from the user pool
	with palloc_get_page().
	Returns true on success, false if UPAGE is already mapped or
	if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable)
{
	struct thread* t = thread_current();

	/* Verify that there's not already a page at that virtual
		address, then map our page there. */
	return (
		 pagedir_get_page(t->pagedir, upage) == NULL
		 && pagedir_set_page(t->pagedir, upage, kpage, writable));
}

// Don't raise a warning about unused function.
// We know that dump_stack might not be called, this is fine.

/*NY NEDAN, tror det är nya platsen för errormeddelandet


#pragma GCC diagnostic ignored "-Wunused-function"
// With the given stack pointer, will try and output the stack to STDOUT. 
static void dump_stack(const void* esp)
{
	printf("*esp is %p\nstack contents:\n", esp);
	hex_dump((int) esp, esp, PHYS_BASE - esp + 16, true);
	// The same information, only more verbose: 
	// It prints every byte as if it was a char and every 32-bit aligned
	//	data as if it was a pointer. 
	void* ptr_save = PHYS_BASE;
	int i = -15;
	while (ptr_save - i >= esp) {
		char* whats_there = (char*) (ptr_save - i);
		// show the address ...
		printf("%x\t", (uint32_t) whats_there);
		// ... printable byte content ...
		if (*whats_there >= 32 && *whats_there < 127)
			printf("%c\t", *whats_there);
		else
			printf(" \t");
		// ... and 32-bit aligned content
		if (i % 4 == 0) {
			uint32_t* wt_uint32 = (uint32_t*) (ptr_save - i);
			printf("%x\t", *wt_uint32);
			printf("\n-------");
			if (i != 0)
				printf("------------------------------------------------");
			else
				printf(" the border between KERNEL SPACE and USER SPACE ");
			printf("-------");
		}
		printf("\n");
		i++;
	}
}
#pragma GCC diagnostic pop
*/