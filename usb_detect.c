/*
 * multi ir daemon for android -
 * Copyright (C) 2015-2018 AllwinnerTech
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <utils/Log.h>
#include <sys/poll.h>
#include <linux/input.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>

#include "verify.h"

#ifdef DEBUG
	#define dbg_printf(fmt, arg...)	printf(fmt, ##arg)
#else
	#define dbg_printf(fmt, arg...)	;
#endif

#define FILENAME_PREFIX			"Storage"
#define USB_MOUNT_PATH			"/mnt/usbhost"
#define USB_FILE_NAME			"factory_usb_detect.bin"
#define LOG_FILE				"/cache/usb_detect_log"
#define USB_PROP_PATH			"/sys/devices/platform/sunxi_usb_udc/usb_device"

int chanage_usb_mode(void)
{
	unsigned char buf[256];
	int ret;
	int fd = open(USB_PROP_PATH, O_RDONLY);
	if (fd < 0) {
		printf("fail to open %s \n", USB_PROP_PATH);
		return -1;
	}

	ret = read(fd, buf, sizeof(buf));

	close(fd);

	return ret;
}

inline int check_file(char *filepath)
{
	int ret;
	FILE *sha1_file = NULL;

	sha1_file = fopen(filepath, "rb");
	if (sha1_file == NULL) {
		printf("Can't open %s\n", filepath);
		return -1;
	}

	ret = verify_file(sha1_file);

	fclose(sha1_file);

	return ret;
}

/**
 * @brief: filter out the valid usb file.
 * @param: name
 * @return: -1 means something error, else the identity.
 */
inline int usb_storage_verify(const char *name)
{
	/* filename prefix filter */
	if (strncmp(name, FILENAME_PREFIX, strlen(FILENAME_PREFIX)))
		return -1;

	return 0;
}

int lookup_file_in_usb_device(char *path)
{
	char usb_file_path[128] = {0};
	DIR *dir = NULL;
	struct dirent *dirent;
	int ret;
	int exist = 0, retry = 90, again;

	path[0] = '\0';
	dir = opendir(USB_MOUNT_PATH);
	if (dir == NULL) {
		printf("Open directory %s failed!\n", USB_MOUNT_PATH);
		return -1;
	} else {
		dbg_printf("Open directory '%s' successfully\n", USB_MOUNT_PATH);
	}

	while (retry--) {
		while ((dirent = readdir(dir))!= NULL) {
			dbg_printf("search directory/file '%s' in '%s'\n", dirent->d_name, USB_MOUNT_PATH);
			ret = usb_storage_verify(dirent->d_name);
			if (ret < 0)
				continue;
			exist = 1;
			sprintf(usb_file_path, "%s/%s/%s", USB_MOUNT_PATH, dirent->d_name, USB_FILE_NAME);
			again = 3;
			while (again--) {
				if (access(usb_file_path, F_OK) == 0)	break;
				sleep(1);
			}

			if (again >= 0) {
				strcpy(path, usb_file_path);
				dbg_printf("Find file %s in usb storage\n", usb_file_path);
				closedir(dir);
				return 0;
			} else {
				printf("Access file '%s' fail! error %d, error = %s\n", usb_file_path, errno, strerror(errno));
			}
		}

		if (!exist) {
			closedir(dir);
			sleep(1);
			dir = opendir(USB_MOUNT_PATH);
			if (dir == NULL) {
				printf("Open directory %s failed!\n", USB_MOUNT_PATH);
				return -1;
			} else {
				dbg_printf("Open directory '%s' successfully\n", USB_MOUNT_PATH);
			}
		} else {
			closedir(dir);
			printf("Find usb storage but has not file %s in it!\n", usb_file_path);
			return -2;
		}
	}

	printf("Can't find usb storage!\n");
	closedir(dir);
	return -3;
}

int notify_process(int nfd)
{
	int res;
	char event_buf[512] = {0};
	char filepath[128] = {0};
	int event_size;
	int event_pos = 0;
	struct inotify_event *event;

	dbg_printf("Notify event, begin to process...\n");
	res = read(nfd, event_buf, sizeof(event_buf));
	if (res < (int)sizeof(*event)) {
		if (errno == EINTR)
			return -1;
		printf("Could not get event!\n");
		return -2;
	}

	while (res >= (int)sizeof(*event)) {
		event = (struct inotify_event *)(event_buf + event_pos);
		dbg_printf("Get event %d: %08x \"%s\"\n",
			event->wd, event->mask, event->len ? event->name : "");

		if (event->mask & IN_CREATE) {
			if (!lookup_file_in_usb_device(filepath)) {
				if (!check_file(filepath))
					chanage_usb_mode();
				else
					printf("verify file %s failed!\n", filepath);
			}
		}

		event_size = sizeof(*event) + event->len;
		res -= event_size;
		event_pos += event_size;
	}

	return 0;
}

int main(void)
{
	int err, nfds;
	const char *inotify_path = "/dev/block";
	struct pollfd ufds[1];

	memset(ufds, 0, sizeof(ufds));
	/* inotify when /dev/block dir change */
	nfds = 1;
	ufds[0].fd = inotify_init();
	ufds[0].events = POLLIN;
	err = inotify_add_watch(ufds[0].fd, inotify_path, IN_CREATE);
	if (err < 0) {
		printf("Could not add watch for %s!\n", inotify_path);
		return -1;
	}

	while (1) {
		poll(ufds, nfds, -1);
		if (ufds[0].revents & POLLIN)
			notify_process(ufds[0].fd);
	}

	return 0;
}
