#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#include "nvram.h"
#include "parser.h"
#include "mosquitto.h"
#include "upload.h"

#define NVRAM_ID 1

#define MAX_ID_LEN 64
#define MAX_PW_LEN 64

typedef struct s_ap_config_info {
	char	config_ver[5];
	char	op_mode[5];
	char	pvs_period[5];

	char	ssid[MAX_ID_LEN];
	char	hidden[5];
	char	password[MAX_PW_LEN];
	char	mode[5];
	char	channel[5];
	char	bandwidth[5];
	char	power[5];

	char	fw_ver[64];
	char	fw_name[64];
	char	fw_md5[64];
	char	fw_download_path[64];
} ACI;
ACI s_aci = {0,};

char mac_address[19] = {0,};
char ip_address[16] = {0,};
char json_mac[50] = "{\"mac_addr\":\"";

typedef struct s_topic{
    char    log[64];
    char    fw_up[64];
    char    config_pvs[64];
    char    state_pvs[64];
    char    error[64];
	char	ping[64];
}TOPIC;
TOPIC topic = {0,};

void make_topic();
void get_state(char*, char*);

int nvram_config_set(char* key, char* value) {
    const char *buf;
    buf = nvram_bufget(NVRAM_ID, key);

    if(strcmp(buf, value) != 0) {
        nvram_bufset(NVRAM_ID, key, value);
        return 1;
    }
    else {
        return 0;
    }
}

void get_data_basic(char* key, char* content) {
	char buf[128] = {0,};

	FILE *fp = NULL;
	fp = popen(content, "r");
	if(fp == NULL) {
		perror("get data fail");
		return;
	}
	else {
		fgets(buf, sizeof(buf), fp);
		pclose(fp);
		strcpy(key, buf);
	}
}

void mosquitto_log(char *);
int get_fw_ver(char *value);

