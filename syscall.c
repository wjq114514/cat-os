#include "kernel.h"
#include "syscall.h"
#include "net.h"
#include "vfs.h"
#include "paging.h"
void syscall_init(void){kputs("[OK] syscall dispatcher initialized (native/Linux shim tables)\n");}
int user_range_ok(uint32_t p,uint32_t n){return p>=0x400000u&&n<=0xBFC00000u-p;}
static int bad_user(const void *p,uint32_t n,int write){return !user_access_ok((uintptr_t)p,n,write);}
static socket_t *sock_fd(int fd){return (socket_t*)vfs_socket_get(fd);}
static int sock_err(int fd){return vfs_fd_exists(fd)?-CATOS_ENOTSOCK:-CATOS_EBADF;}
int32_t syscall_dispatch(uint32_t nr,uint32_t n,const uint32_t *a){
    (void)n;if(!a)return -CATOS_EFAULT;
    if(nr<20)return vfs_syscall(nr,a);
    switch(nr){
    case CATOS_SYS_SOCKET:{
        if(a[0]!=CATOS_SOCK_DGRAM&&a[0]!=CATOS_SOCK_STREAM)return -CATOS_EINVAL;
        socket_t *s=net_socket_open(a[0]);if(!s)return -CATOS_EMFILE;
        int fd=vfs_socket_install(s);if(fd<0){net_socket_close(s);return fd;}return fd;
    }
    case CATOS_SYS_BIND:{socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);return net_socket_bind(s,(uint16_t)a[1]);}
    case CATOS_SYS_LISTEN:{socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);return tcp_set_backlog(s,a[1]);}
    case CATOS_SYS_ACCEPT:{socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);if(s->type!=SOCK_TCP_LISTEN)return -CATOS_EINVAL;socket_t *nxt=tcp_accept_socket(s);if(!nxt)return -CATOS_EAGAIN;int fd=vfs_socket_install(nxt);if(fd<0){tcp_abort_socket(nxt);return fd;}return fd;}
    case CATOS_SYS_SENDTO:{socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);if(bad_user((void*)a[1],a[2],0))return -CATOS_EFAULT;return udp_sendto(s,a[3],(uint16_t)a[4],(const uint8_t*)a[1],a[2]);}
    case CATOS_SYS_RECVFROM:{socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);if(bad_user((void*)a[1],a[2],1)||bad_user((void*)a[3],4,1)||bad_user((void*)a[4],2,1))return -CATOS_EFAULT;int r=udp_recvfrom(s,(uint32_t*)a[3],(uint16_t*)a[4],(uint8_t*)a[1],a[2]);return r<0?-CATOS_EAGAIN:r;}
    case CATOS_SYS_SEND:{socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);if(s->type!=SOCK_TCP_ESTAB)return -CATOS_ENOTCONN;if(bad_user((void*)a[1],a[2],0))return -CATOS_EFAULT;int r=tcp_send(s,(const uint8_t*)a[1],a[2]);return r<0?-CATOS_EAGAIN:r;}
    case CATOS_SYS_RECV:{socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);if(s->type!=SOCK_TCP_ESTAB)return -CATOS_ENOTCONN;if(bad_user((void*)a[1],a[2],1))return -CATOS_EFAULT;int r=tcp_recv(s,(uint8_t*)a[1],a[2]);return r<0?-CATOS_EAGAIN:r;}
    case CATOS_SYS_CLOSE:{if(sock_fd((int)a[0])){int r=net_socket_close(sock_fd((int)a[0]));if(r==0)vfs_socket_close((int)a[0]);return r;}return vfs_close((int)a[0]);}
    case CATOS_SYS_PING:{uint32_t dst;if(bad_user((void*)a[0],16,0)||bad_user((void*)a[1],a[2],1))return -CATOS_EFAULT;if(!net_parse_ipv4((const char*)a[0],&dst)){static const char msg[]="ping: invalid address\n";uint32_t n=sizeof(msg)-1;for(uint32_t i=0;i<a[2];i++)((char*)a[1])[i]='\0';if(n>a[2])n=a[2];for(uint32_t i=0;i<n;i++)((char*)a[1])[i]=msg[i];return (int)n;}return net_ping(dst,(uint16_t)a[3],(uint16_t)a[4],(char*)a[1],a[2]);}
    case CATOS_SYS_PING_STATS:{if(bad_user((void*)a[0],a[1],1))return -CATOS_EFAULT;return net_ping_stats((char*)a[0],a[1]);}
    default:return -CATOS_ENOSYS;
    }
}
