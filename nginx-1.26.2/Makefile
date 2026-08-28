
default:	build

clean:
	rm -rf Makefile /home/wjqawa/osdev/nginx-1.26.2/objs

.PHONY:	default clean

build:
	$(MAKE) -f /home/wjqawa/osdev/nginx-1.26.2/objs/Makefile

install:
	$(MAKE) -f /home/wjqawa/osdev/nginx-1.26.2/objs/Makefile install

modules:
	$(MAKE) -f /home/wjqawa/osdev/nginx-1.26.2/objs/Makefile modules

upgrade:
	/tmp/nginx/sbin/nginx -t

	kill -USR2 `cat /tmp/nginx/logs/nginx.pid`
	sleep 1
	test -f /tmp/nginx/logs/nginx.pid.oldbin

	kill -QUIT `cat /tmp/nginx/logs/nginx.pid.oldbin`

.PHONY:	build install modules upgrade
