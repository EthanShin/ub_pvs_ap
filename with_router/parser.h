#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "json.h"

#define MAX_ID_LEN 64
#define MAX_PW_LEN 64

typedef struct s_ap_config_info{
	char	ssid[MAX_ID_LEN];
	char 	hidden[5];
	char	password[MAX_PW_LEN];
	char 	mode[5];
	char 	channel[5];
	char 	bandwidth[5];
	char 	power[5];
} ACI;

void process_object(json_value* value,char* obj,char* buf);
void process_value(json_value* value,char* obj,char* buf);
void process_array(json_value* value, char* obj,char* buf);
void get_json_data(char* data,char* obj,char* buf);



