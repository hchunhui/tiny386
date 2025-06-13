#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <errno.h>

void drop_root(void)
{
	gid_t gid;
	uid_t uid;

	if (geteuid() != 0) {
		return;
	}

	if ((uid = getuid()) == 0) {
		const char *sudo_uid = secure_getenv("SUDO_UID");
		if (sudo_uid == NULL)
			exit(1);
		errno = 0;
		uid = atoi(sudo_uid);
		if (errno)
			exit(1);
	}

	if ((gid = getgid()) == 0) {
		const char *sudo_gid = secure_getenv("SUDO_GID");
		if (sudo_gid == NULL)
			exit(1);
		errno = 0;
		gid = atoi(sudo_gid);
		if (errno != 0)
			exit(1);
	}

	if (setgid(gid) != 0)
		exit(1);

	if (setuid(uid) != 0)
		exit(1);
}

int tun_create(char *dev, int flags)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
		return fd;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags |= flags;
	if (*dev != '\0')
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);

	return fd;
}

int main(int argc, char *argv[])
{
	if (argc == 1)
		return 127;

	char *p = argv[1];
	char tun_name[IFNAMSIZ];
	int fd = tun_create(tun_name, IFF_TAP | IFF_NO_PI);
	drop_root();

	char tapfd[20];
	sprintf(tapfd, "%d", fd);
	setenv("TAPFD", tapfd, 1);
	return execvp(p, argv + 1);
}
