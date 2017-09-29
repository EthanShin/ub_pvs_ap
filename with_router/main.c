#include "main.h"

void my_message_callback(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message)
{

    printf("============================================================================================\n");
    printf("mid | payload | payloadlen |qos | retain | topic \n");
    printf("%d  | %s      | %d  | %d  | %d  | %s \n", message->mid, (char*)message->payload, message->payloadlen, message->qos, message->retain, message->topic);
    printf("============================================================================================\n");

    if(strstr(message->topic, "/poe_port") != 0) {
        printf("json_mac = %s\n", json_mac);
        printf("topic/port = %s\n", topic.port);
        mosquitto_publish(mosq, NULL, topic.port, strlen(json_mac), json_mac, 1, NULL);
    }
    else if(strstr(message->topic, "/config") != 0) {
        get_json_data((char*)message->payload, "ssid", s_aci.ssid);
        get_json_data((char*)message->payload, "hidden", s_aci.hidden);
        get_json_data((char*)message->payload, "password", s_aci.password);
        get_json_data((char*)message->payload, "mode", s_aci.mode);
        get_json_data((char*)message->payload, "channel", s_aci.channel);
        get_json_data((char*)message->payload, "bandwidth", s_aci.bandwidth);
        get_json_data((char*)message->payload, "power", s_aci.power);

        printf("ssid = %s\n", s_aci.ssid);
        if(nvram_config_set(s_aci)) {
            mosquitto_publish(mosq, NULL, topic.config, strlen("1"), "1", 1, NULL);
            
        }
        else {
            mosquitto_publish(mosq, NULL, topic.config, strlen("0"), "0", 1, NULL);
            //실패 시 행동
        }
    }
    else if(strstr(message->topic, "/state") != 0) {
        printf("state request\n");
        const char *ssid, *power;
        char payload[512];
        ssid = nvram_bufget(1, "SSID1");
        power = nvram_bufget(1, "TxPower");
        get_ip_addr();
        sprintf(payload,"{\"ssid\":\"%s\",\"power\":\"%s\",\"ip\":\"%s\"}", ssid, power, ip_address);
        printf("payload = %s\n", payload);
        mosquitto_publish(mosq, NULL, topic.state, strlen(payload), payload, 1, NULL);
    }
    fflush(stdout);
}

bool check_change_value(char* key, char* value) {   
    const char *buf;
    buf = nvram_bufget(1, key);
    printf("value = %s\n", value);

    if(strcmp(buf, value) != 0) {
        int nvram_id = 1;
        nvram_bufset(nvram_id, key, value);
        return true;
    }
    else {
        return false;
    }
}

int nvram_config_set(ACI s_aci) {
    int nvram_id;
    nvram_id = 1;
    nvram_init(nvram_id);
    int isChanged = 0;

    if(strstr(s_aci.ssid, "#") == NULL) {
        if(check_change_value("SSID1", s_aci.ssid)) {
            isChanged = 1;            
        }
    }
    if(strstr(s_aci.hidden, "#") == NULL) {
        if(check_change_value("HideSSID", s_aci.hidden)) {
            isChanged = 1;
        }
    }
    if(strstr(s_aci.password, "#") == NULL) {
        if(check_change_value("WPAPSK1", s_aci.password)) {
            isChanged = 1;
        }
    }
    if(strstr(s_aci.mode, "#") == NULL) {
        if(check_change_value("WirelessMode", s_aci.mode)) {
            isChanged = 1;
        }
    }
    if(strstr(s_aci.channel, "#") == NULL) {
        if(check_change_value("Channel", s_aci.channel)) {
            isChanged = 1;
        }
    }
    if(strstr(s_aci.bandwidth, "#") == NULL) {
        if(check_change_value("HT_BW", s_aci.bandwidth)) {
            isChanged = 1;
        }
    }
    if(strstr(s_aci.power, "#") == NULL) {
        if(check_change_value("TxPower", s_aci.power)) {
            isChanged = 1;
        }
    }

    if(isChanged == 1) {
        nvram_commit(nvram_id);
        printf("reboot\n");
        system("init_system restart");
    }

    nvram_close(nvram_id);
    return	1;
}

void check_opmode_and_Get_IP(){
   int nvram_id;
   nvram_id = 1;
   nvram_init(nvram_id);

   const char *opmode =NULL;
   opmode = nvram_bufget(nvram_id, "OperationMode");
   if(!strcmp(opmode, "0")) {
      printf("OP mode!!\n");
      system("udhcpc -i br0 -s /sbin/udhcpc.sh -p /var/run/udhcp");
   }
   nvram_close(nvram_id);
}

void my_connect_callback(struct mosquitto *mosq, void *userdata, int result) {
    if(!result) {
        /* Subscribe to broker information topics on successful connect. */
        mosquitto_subscribe(mosq, NULL, "router/poe_port", 1);
        mosquitto_subscribe(mosq, NULL, "router/config", 1);
        mosquitto_subscribe(mosq, NULL, "router/state", 1);
	mosquitto_subscribe(mosq, NULL, "router/ping", 1);
        char temp[40] = {0,};
        sprintf(temp, "router/config/%s", mac_address);
        mosquitto_subscribe(mosq, NULL, temp, 1);

        firstBOOTING();
    }
    else {
        fprintf(stderr, "Connect failed\n");
    }
}

void firstBOOTING() {
    //mosquitto_publish(mosq, NULL, topic.config, strlen(json_mac), json_mac, 1, NULL);
}

void get_router_addr(char* host) {   
    char buf[64];
    FILE *fp = NULL;
    memset(buf, 0x00, 64);
    fp = popen("route | grep -r default | awk '{ print$2 }'", "r");
    if(fp == NULL) {
        perror("get router ip fail");
    }
    else {
        while(fgets(buf, 64, fp)) {
            printf("%s", buf);
        }
        strcpy(host, buf);
        pclose(fp);
    }
}

void get_mac_addr() {
    char buf[64];
    FILE *fp = NULL;
    memset(buf, 0x00, 64);
    fp = popen("ifconfig br0 | grep -r HWaddr | awk '{print$5}'", "r");
    if(fp == NULL) {
        perror("get router ip fail");
    }
    else {
        while(fgets(buf, 64, fp)) {
            printf("%s", buf);
        }
        strcpy(mac_address, buf);
        mac_address[strlen(mac_address) - 1] = '\0';
        strcat(json_mac, mac_address);
        strcat(json_mac, "\"}");
        pclose(fp);
    }
}

void get_ip_addr() {
    char buf[64];
    FILE *fp = NULL;
    memset(buf, 0x00, 64);
    const char *opmode =NULL;
    opmode = nvram_bufget(1, "OperationMode");
    if(!strcmp(opmode, "0")) {
	fp = popen("ifconfig br0 | grep -r addr | awk '{print$2}'", "r");
    }
    else {
	fp = popen("ifconfig eth2.2 | grep -r addr | awk '{print$2}'", "r");
    }
    if(fp == NULL) {
        perror("get router ip fail");
    }
    else {
        while(fgets(buf, 64, fp)) {
            printf("%s", buf);
        }
        char* temp = strrchr(buf, ':') + 1;
        strcpy(ip_address, temp);
        ip_address[strlen(ip_address) - 1] = '\0';
        pclose(fp);
    }
}

void make_topic() {
    char temp[64] = {0,};

    memset(&temp, 0x00, 64);
    sprintf(temp, "ap/poe_port/%s", mac_address);
    strncpy(topic.port, temp, strlen(temp));

    memset(&temp, 0x00, 64);
    sprintf(temp, "ap/config/%s", mac_address);
    strncpy(topic.config, temp, strlen(temp));

    memset(&temp, 0x00, 64);
    sprintf(temp, "ap/state/%s", mac_address);
    strncpy(topic.state, temp, strlen(temp));
}

int main(int argc, char *argv[])
{
    int port = 1883;
    int keepalive = 60;
    bool clean_session = true;
    char host[16];
    check_opmode_and_Get_IP();

    get_router_addr(host);
    get_mac_addr();

    make_topic();

    mosquitto_lib_init();
    mosq = mosquitto_new(NULL, clean_session, NULL);
    if(!mosq){
        fprintf(stderr, "Error: Out of memory.\n");
        return 1;
    }

    mosquitto_connect_callback_set(mosq, my_connect_callback);
    mosquitto_message_callback_set(mosq, my_message_callback);

    while(1) {
        if(mosquitto_connect(mosq, host, port, keepalive)) {
            fprintf(stderr, "Error: Unable to connect.\n");
            sleep(3);
        }
        else break;
    }

    mosquitto_loop_forever(mosq, -1, 1);

    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    return 0;
}
