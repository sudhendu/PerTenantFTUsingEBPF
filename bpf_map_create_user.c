#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <locale.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <getopt.h>
#include <net/if.h>
#include <time.h>

#include "libbpf.h"

static int verbose = 1;
static const char *mapfile = "/sys/fs/bpf/tc/globals/egress_ifindex";
static const char *devtenfile = "/sys/fs/bpf/tc/globals/deviceid_tenant";

struct map_key
{
	__u32 destination_ip;
	__u32 tenant_id;
};

struct map_entry {
	int device_id;
	__u8 dst_mac[6];
};

int main(int argc, char **argv)
{
	char bpf_obj_egress[256], bpf_obj_tenant[256];

	int ret;
	char buf[256];
	sprintf(buf, "ip addr | grep %s", argv[1]);
	FILE *output = popen(buf, "r");
	char *retChar = fgets(buf, 100, output);
	pclose(output);
	__u32 devid = 0;
	int x = 0;
	while(buf[x] != ':')
	{
		devid = devid * 10 + (buf[x] - '0');
		x++;
	}

	int fd_egress = bpf_obj_get(mapfile);
	int fd_tenant = bpf_obj_get(devtenfile);
	if (fd_egress < 0 || fd_tenant < 0) {
		fprintf(stderr, "ERROR: cannot open bpf_obj_get(%s): %s(%d)\n",
				mapfile, strerror(errno), errno);
		ret = EXIT_FAILURE;
	}

	else
	{
		__u32 device_id = devid;
		__u32 tenant_id = atoi(argv[2]);

		__u32 ip = inet_addr(argv[3]);
		__u8 mac[6];
		mac[0] = 0;
		mac[1] = 0;
		mac[2] = 0;
		mac[3] = 0;
		mac[4] = 0;
		mac[5] = 0;
		int place = 0;
		for(int i = 0; i < strlen(argv[4]); i++)
		{
			if(argv[4][i] == ':')
				place++;
			if(argv[4][i] >= '0' && argv[4][i] <= '9')
				mac[place] = mac[place] * 16 + argv[4][i] - '0';
			if(argv[4][i] >= 'a' && argv[4][i] <= 'f')
				mac[place] = mac[place] * 16 + ('f' - argv[4][i]) + 10;
		}

		ret = bpf_map_update_elem(fd_tenant, &device_id, &tenant_id, 0);
		if (ret)
		{
			perror("ERROR: bpf_map_update_elem in tenant_map");
			ret = EXIT_FAILURE;
		}

		struct map_key key;
		key.destination_ip = ip;
		key.tenant_id = tenant_id;

		struct map_entry value;
		value.device_id = device_id;
		value.dst_mac[0] = mac[0];
		value.dst_mac[1] = mac[1];
		value.dst_mac[2] = mac[2];
		value.dst_mac[3] = mac[3];
		value.dst_mac[4] = mac[4];
		value.dst_mac[5] = mac[5];

		ret = bpf_map_update_elem(fd_egress, &key, &value, 0);
		if(ret)
		{
			perror("ERROR: bpf_map_update_elem in egress_map");
			ret = EXIT_FAILURE;
		}
		close(fd_tenant);
		close(fd_egress);
	}
	return ret;
}
