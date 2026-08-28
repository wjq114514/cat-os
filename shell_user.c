/*
 * shell_user.c —— Cat-OS ring3 shell（bash-like 增强版）
 * ─────────────────────────────────────────────────────────────────────────────
 * 功能（参照 bash/ash 行为）：
 *   - Ctrl+C (3)  : 取消当前行，重显提示符
 *   - Ctrl+D (4)  : 空行时 exit，非空行删除光标后字符
 *   - Ctrl+L (12) : 清屏，重显提示符
 *   - Ctrl+U (21) : 清除整行
 *   - Ctrl+A (1)  : 光标移到行首
 *   - Ctrl+E (5)  : 光标移到行尾
 *   - Ctrl+K (11) : 删除光标到行尾
 *   - Ctrl+W (23) : 删除前一个单词
 *   - ↑ (ESC[A)   : 上一条历史
 *   - ↓ (ESC[B)   : 下一条历史
 *   - ← (ESC[D)   : 光标左移
 *   - → (ESC[C)   : 光标右移
 *   - Home (ESC[H) : 光标移到行首
 *   - End  (ESC[F) : 光标移到行尾
 *   - Delete(ESC[3~): 删除光标处字符
 *   - Tab          : 最小补全（命令名 + /mnt/fat/ 路径）
 *
 * int 0x80 调用约定：EAX=nr, EBX/ECX/EDX/ESI/EDI → a[0..4]
 *
 * 编译：见 Makefile「── code2: ring3 shell ──」段
 */
#include <stdint.h>

/* ── 系统调用封装 ────────────────────────────────────────────────────── */
static int32_t syscall3(uint32_t nr, uint32_t a0, uint32_t a1, uint32_t a2)
{
    int32_t ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(nr), "b"(a0), "c"(a1), "d"(a2)
                     : "memory");
    return ret;
}
static int32_t syscall5(uint32_t nr, uint32_t a0, uint32_t a1, uint32_t a2,
                        uint32_t a3, uint32_t a4)
{
    int32_t ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(nr), "b"(a0), "c"(a1), "d"(a2),
                       "S"(a3), "D"(a4)
                     : "memory");
    return ret;
}
static int32_t sys_read(uint32_t fd, void *buf, uint32_t len)
{ return syscall3(0u, fd, (uint32_t)buf, len); }
static int32_t sys_write(uint32_t fd, const void *buf, uint32_t len)
{ return syscall3(1u, fd, (uint32_t)buf, len); }
static int32_t sys_exec(const char *path)
{ return syscall3(11u, (uint32_t)path, 0u, 0u); }
static int32_t sys_exit(uint32_t status)
{ return syscall3(12u, status, 0u, 0u); }
static int32_t sys_open(const char *path, uint32_t flags)
{ return syscall3(5u, (uint32_t)path, flags, 0u); }
static int32_t sys_close(uint32_t fd)
{ return syscall3(6u, fd, 0u, 0u); }

#define CATOS_SYS_NET_STATS 32u
#define CATOS_SYS_RESOLVE   31u
static int32_t sys_net_stats(uint32_t *buf, uint32_t cap)
{ return syscall3(CATOS_SYS_NET_STATS, (uint32_t)buf, cap, 0u); }
static int32_t sys_resolve(const char *name, uint32_t *out_ip)
{ return syscall3(CATOS_SYS_RESOLVE, (uint32_t)name, (uint32_t)out_ip, 0u); }
static int32_t sys_ping(const char *target, char *out, uint32_t out_len,
                        uint32_t id, uint32_t seq)
{ return syscall5(29u, (uint32_t)target, (uint32_t)out, out_len, id, seq); }

/* ── 常量 ────────────────────────────────────────────────────────────── */
#define SHELL_LINE_MAX  256u
#define HISTORY_SIZE    16u
#define PROMPT          "cat-os$ "
#define PROMPT_LEN      7u

/* 控制字符 */
#define CTRL_A  1   /* 光标移到行首 */
#define CTRL_D  4   /* EOF / 删除后半行 */
#define CTRL_E  5   /* 光标移到行尾 */
#define CTRL_K  11  /* 删除到行尾 */
#define CTRL_L  12  /* 清屏 */
#define CTRL_U  21  /* 清除整行 */
#define CTRL_W  23  /* 删除前一单词 */
#define CTRL_C  3   /* 取消当前行 */
#define CTRL_Z  26  /* 暂无操作（无 job control） */

/* ── 极小运行时（无 libc）──────────────────────────────────────────── */
static uint32_t kstrlen(const char *s){uint32_t n=0;while(s[n])n++;return n;}
static int kstrcmp(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return(int)(unsigned char)*a-(int)(unsigned char)*b;}
static int kstrncmp(const char *a,const char *b,uint32_t n){for(uint32_t i=0;i<n;i++){if(a[i]!=b[i])return(int)(unsigned char)a[i]-(int)(unsigned char)b[i];if(!a[i])break;}return 0;}
static void *kmemcpy(void *d,const void *s,uint32_t n){for(uint32_t i=0;i<n;i++)((char*)d)[i]=((const char*)s)[i];return d;}

static void print(const char *s){sys_write(1u,s,kstrlen(s));}
static void print_n(const char *s,uint32_t n){sys_write(1u,s,n);}
static void print_char(char c){sys_write(1u,&c,1u);}

/* ── 数字输出 ────────────────────────────────────────────────────────── */
static void print_u32(uint32_t v){
    char b[10];int i=0;
    if(v==0)b[i++]='0';
    while(v>0){b[i++]=(char)('0'+v%10);v/=10;}
    char out[10];int j=0;
    while(i>0)out[j++]=b[--i];
    sys_write(1u,out,(uint32_t)j);
}
static void print_i32(int32_t v){
    if(v<0){print_char('-');print_u32((uint32_t)(-(v+1))+1u);return;}
    print_u32((uint32_t)v);
}

/* ── ANSI 转义序列输出 ──────────────────────────────────────────────── */
static void esc_clear_screen(void){print("\x1b[2J\x1b[H");}       /* 清屏 + 光标归位 */
static void esc_cursor_left(uint32_t n){print("\x1b[");print_u32(n);print_char('D');}
static void esc_cursor_right(uint32_t n){print("\x1b[");print_u32(n);print_char('C');}
static void esc_cursor_to_col(uint32_t col){print("\x1b[");print_u32(col+1);print_char('G');}
static void esc_erase_line(void){print("\x1b[2K");}                /* 清除整行 */
static void esc_erase_to_end(void){print("\x1b[K");}               /* 清除光标到行尾 */

/* ── 命令历史 ────────────────────────────────────────────────────────── */
static char history[HISTORY_SIZE][SHELL_LINE_MAX];
static uint32_t hist_count=0, hist_idx=0; /* hist_idx=hist_count 表示"新输入"行 */

static void hist_push(const char *line,uint32_t len){
    if(len==0)return;
    /* 去重：与最近一条相同则不入 */
    if(hist_count>0){
        uint32_t last=(hist_count-1)%HISTORY_SIZE;
        if(kstrcmp(history[last],line)==0)return;
    }
    uint32_t idx=hist_count%HISTORY_SIZE;
    kmemcpy(history[idx],line,len+1);
    hist_count++;
    hist_idx=hist_count; /* 指向新输入 */
}
static const char *hist_up(void){
    if(hist_count==0)return (const char*)0;
    if(hist_idx==hist_count) hist_idx=hist_count-1;
    else if(hist_idx>0) hist_idx--;
    return history[hist_idx%HISTORY_SIZE];
}
static const char *hist_down(void){
    if(hist_count==0)return (const char*)0;
    if(hist_idx<hist_count-1){hist_idx++;return history[hist_idx%HISTORY_SIZE];}
    hist_idx=hist_count;
    return (const char*)0; /* 回到新输入行 */
}

/* ── Tab 补全（最小可用）──────────────────────────────────────────────
 * 内置命令名列表 + /mnt/fat/ 路径补全。
 * 仅在光标位于行尾时触发（简化实现）。 */
static const char *const builtins[]={
    "echo","help","netstat","resolve","ping","nginx","exec","exit","ls","cat","history",
    (const char*)0
};
static int try_complete(char *buf,uint32_t len,uint32_t *cursor){
    if(*cursor!=len)return 0; /* 仅行尾触发 */
    /* 找到当前单词起点 */
    uint32_t start=*cursor;
    while(start>0&&buf[start-1]!=' ')start--;
    uint32_t wordlen=*cursor-start;
    if(wordlen==0)return 0;
    /* 在内置命令中匹配 */
    int match_count=0;const char *match=(const char*)0;
    for(const char *const *b=builtins;b[0];b++){
        if(kstrncmp(b[0]+0,buf+start,wordlen)==0){
            match=b[0];match_count++;
        }
    }
    if(match_count==1&&match){
        /* 唯一匹配：补全剩余部分 */
        uint32_t compl_len=kstrlen(match)-wordlen;
        if(*cursor+compl_len<SHELL_LINE_MAX-1){
            kmemcpy(buf+*cursor,match+wordlen,compl_len);
            print_n(match+wordlen,compl_len);
            *cursor+=compl_len;
            buf[*cursor]=' ';
            print_char(' ');
            (*cursor)++;
            buf[*cursor]='\0';
        }
        return 1;
    }
    if(match_count>1){
        /* 多匹配：响铃 */
        print_char('\x07');
        return 1;
    }
    return 0;
}

/* ── readline（bash-like 增强版）────────────────────────────────────── */
static int32_t read_line(char *buf,uint32_t max){
    uint32_t len=0,cursor=0;
    buf[0]='\0';

    for(;;){
        char c;
        int32_t r=sys_read(0u,&c,1u);
        if(r<=0)continue;

        /* ── ESC 序列解析 ── */
        if(c=='\x1b'){
            /* 读 '[' */
            char c2; r=sys_read(0u,&c2,1u);
            if(r<=0)continue;
            if(c2!='['){
                /* 非 CSI 序列：忽略 */
                continue;
            }
            /* 读序列标识符 */
            char c3; r=sys_read(0u,&c3,1u);
            if(r<=0)continue;

            /* 箭头键 / Home / End / Delete */
            if(c3=='A'){ /* Up → 历史上一条 */
                const char *prev=hist_up();
                if(prev){
                    /* 清除当前显示行 */
                    esc_cursor_to_col(PROMPT_LEN);
                    esc_erase_line();
                    print(PROMPT);
                    len=kstrlen(prev);cursor=len;
                    kmemcpy(buf,prev,len+1);
                    print_n(buf,len);
                }
                continue;
            }
            if(c3=='B'){ /* Down → 历史下一条 */
                const char *next=hist_down();
                esc_cursor_to_col(PROMPT_LEN);
                esc_erase_line();
                print(PROMPT);
                if(next){
                    len=kstrlen(next);cursor=len;
                    kmemcpy(buf,next,len+1);
                    print_n(buf,len);
                }else{
                    len=0;cursor=0;buf[0]='\0';
                }
                continue;
            }
            if(c3=='C'){ /* Right → 光标右移 */
                if(cursor<len){cursor++;esc_cursor_right(1);}
                continue;
            }
            if(c3=='D'){ /* Left → 光标左移 */
                if(cursor>0){cursor--;esc_cursor_left(1);}
                continue;
            }
            if(c3=='H'){ /* Home → 行首 */
                if(cursor>0){esc_cursor_left(cursor);cursor=0;}
                continue;
            }
            if(c3=='F'){ /* End → 行尾 */
                if(cursor<len){esc_cursor_right(len-cursor);cursor=len;}
                continue;
            }
            if(c3=='3'){ /* Delete */
                char c4; r=sys_read(0u,&c4,1u);
                if(r<=0)continue;
                if(c4=='~'){
                    if(cursor<len){
                        /* 移除 cursor 处字符 */
                        for(uint32_t i=cursor;i<len;i++) buf[i]=buf[i+1];
                        len--;
                        /* 重绘：光标处到行尾 + 回退 */
                        esc_erase_to_end();
                        print_n(buf+cursor,len-cursor);
                        esc_cursor_to_col(PROMPT_LEN+cursor);
                    }
                }
                continue;
            }
            /* 未识别 CSI：忽略 */
            continue;
        }

        /* ── 普通控制字符 ── */
        if(c==CTRL_C){
            /* 取消当前行：清行，重显提示符 */
            print("^C\n");
            len=0;cursor=0;buf[0]='\0';
            print(PROMPT);
            continue;
        }
        if(c==CTRL_D){
            if(len==0){
                /* 空行 Ctrl+D = exit */
                print("\nexit\n");
                sys_exit(0u);
            }
            /* 非空行：删除光标处字符（同 Delete） */
            if(cursor<len){
                for(uint32_t i=cursor;i<len;i++) buf[i]=buf[i+1];
                len--;
                esc_erase_to_end();
                print_n(buf+cursor,len-cursor);
                esc_cursor_to_col(PROMPT_LEN+cursor);
            }
            continue;
        }
        if(c==CTRL_L){
            esc_clear_screen();
            print(PROMPT);
            print_n(buf,len);
            esc_cursor_to_col(PROMPT_LEN+cursor);
            continue;
        }
        if(c==CTRL_U){
            if(cursor>0){
                /* 移除 [0..cursor) 内容 */
                uint32_t rem=len-cursor;
                kmemcpy(buf,buf+cursor,rem);
                len=rem;cursor=0;
                buf[len]='\0';
                esc_cursor_to_col(PROMPT_LEN);
                esc_erase_to_end();
                print_n(buf,len);
                esc_cursor_to_col(PROMPT_LEN);
            }
            continue;
        }
        if(c==CTRL_K){
            if(cursor<len){
                esc_erase_to_end();
                len=cursor;buf[len]='\0';
            }
            continue;
        }
        if(c==CTRL_A){
            if(cursor>0){esc_cursor_left(cursor);cursor=0;}
            continue;
        }
        if(c==CTRL_E){
            if(cursor<len){esc_cursor_right(len-cursor);cursor=len;}
            continue;
        }
        if(c==CTRL_W){
            /* 删除前一单词 */
            if(cursor>0){
                uint32_t end=cursor;
                while(cursor>0&&(buf[cursor-1]==' '))cursor--;
                while(cursor>0&&(buf[cursor-1]!=' '))cursor--;
                uint32_t del=end-cursor;
                kmemcpy(buf+cursor,buf+end,len-end+1);
                len-=del;
                /* 重绘 */
                esc_cursor_to_col(PROMPT_LEN+cursor);
                esc_erase_to_end();
                print_n(buf+cursor,len-cursor);
                esc_cursor_to_col(PROMPT_LEN+cursor);
            }
            continue;
        }

        /* ── 回车 ── */
        if(c=='\n'||c=='\r'){
            print_char('\n');
            buf[len]='\0';
            if(len>0) hist_push(buf,len);
            return (int32_t)len;
        }

        /* ── 退格 ── */
        if(c=='\b'||c==127){
            if(cursor>0){
                cursor--;
                for(uint32_t i=cursor;i<len;i++) buf[i]=buf[i+1];
                len--;
                buf[len]='\0';
                /* 重绘：退格 + 重显光标后内容 + 回退光标 */
                esc_cursor_left(1);
                esc_erase_to_end();
                print_n(buf+cursor,len-cursor);
                esc_cursor_to_col(PROMPT_LEN+cursor);
            }
            continue;
        }

        /* ── Tab 补全 ── */
        if(c=='\t'){
            try_complete(buf,len,&cursor);
            continue;
        }

        /* ── 可见字符：插入 ── */
        if(c>=32&&c<127&&len+1u<max){
            /* 在光标处插入字符 */
            for(uint32_t i=len;i>cursor;i--) buf[i]=buf[i-1];
            buf[cursor]=c;
            len++;cursor++;
            buf[len]='\0';
            /* 重绘：光标处到行尾 + 回退光标 */
            esc_erase_to_end();
            print_n(buf+cursor-1,len-cursor+1);
            esc_cursor_to_col(PROMPT_LEN+cursor);
        }
    }
}

/* ── Token 解析 ──────────────────────────────────────────────────────── */
static char *next_token(char **rest){
    char *s=*rest;
    while(*s==' ')s++;
    if(*s=='\0'){*rest=s;return (char*)0;}
    char *tok=s;
    while(*s&&*s!=' ')s++;
    if(*s==' '){*s='\0';s++;while(*s==' ')s++;}
    *rest=s;
    return tok;
}

/* ── 内置命令 ────────────────────────────────────────────────────────── */
static void cmd_echo(const char *args){
    if(*args=='\0'){print_char('\n');return;}
    print(args);print_char('\n');
}
static void cmd_help(void){
    print("Cat-OS shell commands:\n");
    print("  echo <text>      print text\n");
    print("  help             list commands\n");
    print("  netstat          show network counters\n");
    print("  resolve <host>   DNS resolve\n");
    print("  ping <IPv4>      send one ICMP echo request\n");
    print("  nginx            start embedded nginx on :8080\n");
    print("  exec <path>      run ELF32 program\n");
    print("  ls <path>        list FAT16 directory\n");
    print("  cat <path>       print file contents\n");
    print("  history          show command history\n");
    print("  exit             terminate shell\n");
    print("\nKey bindings:\n");
    print("  Ctrl+C  cancel line    Ctrl+L  clear screen\n");
    print("  Ctrl+A  line start     Ctrl+E  line end\n");
    print("  Ctrl+U  clear line     Ctrl+K  clear to end\n");
    print("  Ctrl+W  delete word    Ctrl+D  EOF / delete char\n");
    print("  Up/Down history        Left/Right cursor\n");
    print("  Tab                   auto-complete\n");
}

/* netstat */
enum {
    NS_ARP_REQ_OUT, NS_ARP_REPLY_IN, NS_ARP_RESOLVE_MISS, NS_IP_CSUM_ERR,
    NS_ETHERTYPE_UNKNOWN, NS_UDP_NO_LISTENER, NS_RX_DROP_FULL,
    NS_TCP_RST_SENT, NS_TCP_RTO_REXMIT, NS_TCP_SACK_REXMIT,
    NS_TCP_PERSIST_PROBE, NS_ICMP_ECHO_OUT, NS_ARP_ENTRY_EXPIRED,
    NS_COUNT
};
static const char *const ns_names[NS_COUNT]={
    "arp_req_out","arp_reply_in","arp_resolve_miss","ip_csum_err",
    "ethertype_unknown","udp_no_listener","rx_drop_full","tcp_rst_sent",
    "tcp_rto_rexmit","tcp_sack_rexmit","tcp_persist_probe","icmp_echo_out",
    "arp_entry_expired"
};
static void cmd_netstat(void){
    static uint32_t st[NS_COUNT];
    int32_t r=sys_net_stats(st,(uint32_t)NS_COUNT);
    if(r<=0||r>(int32_t)NS_COUNT){print("netstat: failed\n");return;}
    print("--- net stack counters ---\n");
    for(uint32_t i=0;i<(uint32_t)r;i++){
        print("  ");print(ns_names[i]);
        for(uint32_t p=kstrlen(ns_names[i]);p<20u;p++)print_char(' ');
        print_u32(st[i]);print_char('\n');
    }
}

/* resolve */
static void print_ip(uint32_t ip_be){
    const uint8_t *b=(const uint8_t*)&ip_be;
    for(uint32_t i=0;i<4u;i++){print_u32(b[i]);if(i<3u)print_char('.');}
}
static void cmd_resolve(const char *host){
    if(*host=='\0'){print("resolve: usage: resolve <host>\n");return;}
    static uint32_t ip;
    int32_t r=sys_resolve(host,&ip);
    if(r==0){print(host);print(" -> ");print_ip(ip);print_char('\n');return;}
    print("resolve: ");print(host);print(" failed (errno ");print_i32(r);print(")\n");
}

/* ping */
static void cmd_ping(const char *args){
    char *rest=(char*)args;
    char *host=next_token(&rest);
    if(!host||*host=='\0'){print("ping: usage: ping <IPv4>\n");return;}
    static char out[128];
    static uint32_t seq;
    int32_t r=sys_ping(host,out,sizeof(out)-1u,0xCA70u,seq++);
    if(r<0){print("ping: failed (errno ");print_i32(-r);print(")\n");return;}
    print_n(out,(uint32_t)r);
}

/* nginx */
static void cmd_nginx(const char *args){
    (void)args;
    static int32_t nginx_pid=-1;
    if(nginx_pid>0){
        print("nginx: already started (pid=");print_i32(nginx_pid);print(")\n");
        return;
    }
    nginx_pid=sys_exec("/bin/nginx");
    if(nginx_pid<0){print("nginx: failed (errno ");print_i32(-nginx_pid);print(")\n");return;}
    print("nginx: started (pid=");print_i32(nginx_pid);print(")\n");
}

/* exec */
static void cmd_exec(const char *path){
    if(*path=='\0'){print("exec: usage: exec <path>\n");return;}
    int32_t pid=sys_exec(path);
    if(pid<0){print("exec: failed (errno ");print_i32(-pid);print(")\n");return;}
    print("exec: pid=");print_i32(pid);print_char('\n');
}

/* ls — 最小 FAT16 目录列表（走 open/read 演示） */
static void cmd_ls(const char *path){
    if(*path=='\0') path="/mnt/fat/";
    int fd=sys_open(path,0);
    if(fd<0){print("ls: open failed (");print_i32(fd);print(")\n");return;}
    /* 简单打印：读取目录内容（devfs/blk 暂不支持 readdir，仅展示 open 成功） */
    print("ls: opened ");print(path);print(" fd=");print_i32(fd);print_char('\n');
    sys_close(fd);
}

/* cat — 读文件内容 */
static void cmd_cat(const char *path){
    if(*path=='\0'){print("cat: usage: cat <path>\n");return;}
    int fd=sys_open(path,0);
    if(fd<0){print("cat: open failed (");print_i32(fd);print(")\n");return;}
    char buf[512];
    for(;;){
        int32_t n=sys_read(fd,buf,sizeof(buf));
        if(n<=0)break;
        print_n(buf,(uint32_t)n);
    }
    sys_close(fd);
}

/* history */
static void cmd_history(void){
    if(hist_count==0){print("no history\n");return;}
    uint32_t start=(hist_count>HISTORY_SIZE)?hist_count-HISTORY_SIZE:0;
    for(uint32_t i=start;i<hist_count;i++){
        print_u32(i+1);print_char(' ');
        print(history[i%HISTORY_SIZE]);print_char('\n');
    }
}

/* ── 主循环 ──────────────────────────────────────────────────────────── */
static void shell_repl(void){
    static char line[SHELL_LINE_MAX];

    esc_clear_screen();
    print("Cat-OS shell v2 (ring3)\n");
    print("type 'help' for commands\n\n");

    for(;;){
        print(PROMPT);
        int32_t n=read_line(line,SHELL_LINE_MAX);
        if(n<=0)continue;
        char *rest=line;
        char *cmd=next_token(&rest);
        if(!cmd)continue;

        if(kstrcmp(cmd,"echo")==0)        cmd_echo(rest);
        else if(kstrcmp(cmd,"help")==0)   cmd_help();
        else if(kstrcmp(cmd,"netstat")==0) cmd_netstat();
        else if(kstrcmp(cmd,"resolve")==0) cmd_resolve(rest);
        else if(kstrcmp(cmd,"ping")==0)    cmd_ping(rest);
        else if(kstrcmp(cmd,"nginx")==0)   cmd_nginx(rest);
        else if(kstrcmp(cmd,"exec")==0)    cmd_exec(rest);
        else if(kstrcmp(cmd,"ls")==0)      cmd_ls(rest);
        else if(kstrcmp(cmd,"cat")==0)     cmd_cat(rest);
        else if(kstrcmp(cmd,"history")==0) cmd_history();
        else if(kstrcmp(cmd,"exit")==0){print("bye\n");sys_exit(0u);}
        else{print(cmd);print(": command not found\n");}
    }
}

/* ── ELF 入口 ────────────────────────────────────────────────────────── */
__attribute__((noreturn)) void _start(void){
    shell_repl();
    for(;;)sys_exit(1u);
}
