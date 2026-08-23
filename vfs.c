#include "vfs.h"
#include "kernel.h"
#include "keyboard.h"
#include "paging.h"
#include <stdint.h>
static file_t *fds[VFS_MAX_FD]; static uint32_t rnd=0x12345678;
static int nullread(struct file*f,void*b,uint32_t n){(void)f;(void)b;(void)n;return 0;} static int nullwrite(struct file*f,const void*b,uint32_t n){(void)f;(void)b;return (int)n;}
static int conwrite(struct file*f,const void*b,uint32_t n){(void)f;const char*p=b;for(uint32_t i=0;i<n;i++){char c=p[i];if(c) {char s[2]={c,0};kputs(s);}}return n;}
static int kread(struct file*f,void*b,uint32_t n){(void)f;uint8_t*p=b;uint32_t i=0;while(i<n){int c=keyboard_getchar();if(c<0)break;p[i++]=(uint8_t)c;}return (int)i;}
static int zread(struct file*f,void*b,uint32_t n){(void)f;for(uint32_t i=0;i<n;i++)((uint8_t*)b)[i]=0;return n;} static int urread(struct file*f,void*b,uint32_t n){(void)f;for(uint32_t i=0;i<n;i++){rnd=rnd*1664525u+1013904223u;((uint8_t*)b)[i]=(uint8_t)(rnd>>24);}return n;}
static const file_ops_t noops={nullread,nullwrite,0},conops={0,conwrite,0},kop={kread,0,0},zops={zread,0,0},uops={urread,0,0};
static inode_t nodes[]={{VFS_CHR,0,"/dev/null",&noops,0},{VFS_CHR,0,"/dev/console",&conops,0},{VFS_CHR,0,"/dev/kbd",&kop,0},{VFS_CHR,0,"/dev/zero",&zops,0},{VFS_CHR,0,"/dev/urandom",&uops,0}};
void vfs_init(void){kputs("[OK] VFS mounted /dev (devfs)\n");for(unsigned i=0;i<3;i++){int fd=vfs_open(nodes[i].name,O_RDWR);if(fd>=0){kputs("[OK] VFS dev node open test ");kputs(nodes[i].name);kputs("\n");vfs_close(fd);}}}
int vfs_open(const char*p,uint32_t fl){for(unsigned i=0;i<sizeof(nodes)/sizeof(nodes[0]);i++){const char*a=p,*b=nodes[i].name;while(*a&&*a==*b){a++;b++;}if(!*a&&!*b)for(int fd=3;fd<VFS_MAX_FD;fd++)if(!fds[fd]){static file_t fs[VFS_MAX_FD];fs[fd]=(file_t){&nodes[i],0,fl,FILE_VFS,0};fds[fd]=&fs[fd];return fd;}}return -1;}
int vfs_read(int fd,void*b,uint32_t n){if(fd<0||fd>=VFS_MAX_FD||!fds[fd]||fds[fd]->kind!=FILE_VFS||!fds[fd]->inode->ops->read)return -9;if(!user_access_ok((uintptr_t)b,n,1))return -14;return fds[fd]->inode->ops->read(fds[fd],b,n);}int vfs_write(int fd,const void*b,uint32_t n){if(!user_access_ok((uintptr_t)b,n,0))return -14;if(fd<0||fd>=VFS_MAX_FD||!fds[fd]||fds[fd]->kind!=FILE_VFS||!fds[fd]->inode->ops->write)return -9;return fds[fd]->inode->ops->write(fds[fd],b,n);}int vfs_close(int fd){if(fd<3||fd>=VFS_MAX_FD||!fds[fd])return -9;if(fds[fd]->kind!=FILE_VFS)return -9;fds[fd]=0;return 0;}
int vfs_socket_install(void *sock){static file_t fs[VFS_MAX_FD];for(int fd=3;fd<VFS_MAX_FD;fd++)if(!fds[fd]){fs[fd]=(file_t){0,0,O_RDWR,FILE_SOCKET,sock};fds[fd]=&fs[fd];return fd;}return -24;}
void *vfs_socket_get(int fd){if(fd<0||fd>=VFS_MAX_FD||!fds[fd]||fds[fd]->kind!=FILE_SOCKET)return 0;return fds[fd]->private;}
int vfs_socket_close(int fd){if(!vfs_socket_get(fd))return -9;fds[fd]=0;return 0;}
int vfs_fd_exists(int fd){return fd>=0&&fd<VFS_MAX_FD&&fds[fd]!=0;}
int32_t vfs_syscall(uint32_t nr,const uint32_t*a){if(nr==5){if(!user_access_ok(a[0],1,0))return -14;return vfs_open((const char*)a[0],a[1]);}if(nr==6)return vfs_close(a[0]);if(nr==3)return vfs_close(a[0]);if(nr==0)return vfs_read(a[0],(void*)a[1],a[2]);if(nr==1)return vfs_write(a[0],(const void*)a[1],a[2]);return -38;}
