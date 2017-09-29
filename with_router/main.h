#include <unistd.h>
#include <sys/ioctl.h>
#include "nvram.h"
#include "parser.h"
#include "mosquitto.h"
#include "convertUTF.h"

ACI s_aci = {0,};
char mac_address[19] = {0,};
char ip_address[16] = {0,};
char json_mac[50] = "{\"mac_addr\":\"";
struct mosquitto *mosq;

typedef struct s_topic{
	char 	port[64];
    char    config[64];
    char    state[64];
}TOPIC;
TOPIC topic = {0,};

void firstBOOTING();
int nvram_config_set(ACI s_aci);
void get_router_addr(char* host);
void get_mac_addr();
void get_ip_addr();
void make_topic();
bool check_change_value(char* key, char* value);
void get_state(char*, char*);
