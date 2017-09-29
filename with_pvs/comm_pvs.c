#include "comm_pvs.h"

struct mosquitto *mosq;

void escapeStr(const char* str) {
    for(; *str != '\0'; str++) {
        if(*str == ':') {
            strcpy(str, str + 1);
            str--;
        }
    }
}

void sigint_handler(int signo) {
	
	char payload[512];
	mosquitto_log(payload);

	
	printf("payload = %s\n", payload);
	mosquitto_publish(mosq, NULL, topic.log, strlen(payload), payload, 1, NULL);
	mosquitto_publish(mosq, NULL, topic.fw_up, strlen(""), "", 1, NULL);

	alarm(atoi(nvram_bufget(NVRAM_ID, "pvs_period")));
}

void my_message_callback(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message)
{

    printf("============================================================================================\n");
    printf("mid | payload | payloadlen |qos | retain | topic \n");
    printf("%d  | %s      | %d  | %d  | %d  | %s \n", message->mid, (char*)message->payload, message->payloadlen, message->qos, message->retain, message->topic);
    printf("============================================================================================\n");

    if(strstr(message->topic, "/fw_up") != 0) {
		
        char cmd[512];
		char md5sum_value[64]={0,};
		char buf2[128]={0,};
        int status;
        const char *buf;
		FILE *fp;
		char temp[8]={0,};

        get_json_data((char*)message->payload, "fw_ver", s_aci.fw_ver);
        get_json_data((char*)message->payload, "fw_name", s_aci.fw_name);
        get_json_data((char*)message->payload, "fw_md5", s_aci.fw_md5);
        get_json_data((char*)message->payload, "fw_download_path", s_aci.fw_download_path);
	
        get_fw_ver(&temp[0]);
        if(strcmp(s_aci.fw_ver,temp)<=0)
        {
                printf("not update firmware ver %s\n",temp);
				mosquitto_publish(mosq, NULL, topic.config_pvs, strlen(""), "", 1, NULL);
                return ;
        }
	
        snprintf(cmd, sizeof(cmd), "rm /tmp/%s", s_aci.fw_name);
        system(cmd);

        snprintf(cmd, sizeof(cmd), "wget %s -P /tmp", s_aci.fw_download_path);
        if(system(cmd) != 0) {
            return ;
        }

        snprintf(cmd, sizeof(cmd), "exec md5sum /tmp/%s", s_aci.fw_name);
        if((fp = popen(cmd,"r"))!=NULL)
        {
                if(fgets(buf2,128,fp)!=NULL)
                        strncpy(md5sum_value,buf2,32);

                pclose(fp);
        }
		else
		{
			printf("popen error\n");
		}

	    if (!strcmp(md5sum_value,s_aci.fw_md5) && strlen(md5sum_value) != 0)
        {
        	printf("Firmware download complete.\n");
            printf("md5sum same goto mtd write\n");
      	}
	    else
  	    { 
            if(strlen(md5sum_value) == 0)
            {
               	printf("fw download fail\n");
           		mosquitto_publish(mosq, NULL, topic.error, strlen("1"), "1", 1, NULL);
                   return ;
                }
            else
            {
                printf("md5sum mismatch\n");
          		mosquitto_publish(mosq, NULL, topic.error, strlen("1"), "1", 1, NULL);
                return ;
            }
      	}

		char filename[64];
		int fw_size = 0;
		FILE *fd = NULL;
		sprintf(filename, "/tmp/%s", s_aci.fw_name);
		printf("file open\n");
		fd = fopen(filename, "rb");
	    fseek(fd, 0L, SEEK_END);
	    fw_size = ftell(fd);
	    fseek(fd, 0, SEEK_SET);
	    fclose(fd);

		printf("pre write\n");
		if( mtd_write_firmware(filename, 0, fw_size) == -1) {
			printf("error\n");
		}

	/*
        snprintf(cmd, sizeof(cmd), "/bin/mtd_write write /tmp/%s Kernel", s_aci.fw_name);
        if(system(cmd) != 0) {
            return ;
        }
	*/

        printf("Firmware write complete.\n");
        nvram_config_set("fw_ver", s_aci.fw_ver);
        nvram_config_set("fw_md5", s_aci.fw_md5);
        nvram_bufset(NVRAM_ID, "state", "2");

        nvram_commit(NVRAM_ID);
        system("reboot");
    
    }
    else if(strstr(message->topic, "/config") != 0) {
        int isChanged = 0;

        get_json_data((char*)message->payload, "config_ver", s_aci.config_ver);
        get_json_data((char*)message->payload, "op_mode", s_aci.op_mode);
        get_json_data((char*)message->payload, "ssid", s_aci.ssid);
        get_json_data((char*)message->payload, "hidden", s_aci.hidden);
        get_json_data((char*)message->payload, "password", s_aci.password);
        get_json_data((char*)message->payload, "mode", s_aci.mode);
        get_json_data((char*)message->payload, "channel", s_aci.channel);
        get_json_data((char*)message->payload, "bandwidth", s_aci.bandwidth);
        get_json_data((char*)message->payload, "power", s_aci.power);
        get_json_data((char*)message->payload, "pvs_period", s_aci.pvs_period);

        isChanged |= nvram_config_set("config_ver", s_aci.config_ver);
        isChanged |= nvram_config_set("OperationMode", s_aci.op_mode);
        isChanged |= nvram_config_set("SSID1", s_aci.ssid);
        isChanged |= nvram_config_set("HideSSID", s_aci.hidden);
        isChanged |= nvram_config_set("WPAPSK1", s_aci.password);
        isChanged |= nvram_config_set("WirelessMode", s_aci.mode);
        isChanged |= nvram_config_set("Channel", s_aci.channel);
        isChanged |= nvram_config_set("HT_BW", s_aci.bandwidth);
        isChanged |= nvram_config_set("TxPower", s_aci.power);
        isChanged |= nvram_config_set("pvs_period", s_aci.pvs_period);
        
        if(isChanged == 1) {
		if(s_aci.op_mode == '1') nvram_config_set("hwnatEnabled", "1");
	        else nvram_config_set("hwnatEnabled", "0");

            nvram_bufset(NVRAM_ID, "state", "3");
            nvram_commit(NVRAM_ID);
	    
	    struct mosquitto *mosq_host;
	    char t[30] = "ap/set/";
	    char payload[512];
	    char hostip[16];
	    strcat(t, mac_address);
	    get_data_basic(hostip, "exec route | grep -r default | awk '{ print$2}'");
	    hostip[strlen(hostip) - 1] = '\0';
	    mosq_host = mosquitto_new(NULL, true, NULL);
	    mosquitto_connect(mosq_host, hostip, 1883, 60);
	    
	    sprintf(payload,"ssid:%s,password:%s,mode:%s,channel:%s,bandwidth:%s,power:%s,hidden:%s", s_aci.ssid, s_aci.password, s_aci.mode, s_aci.channel, s_aci.bandwidth, s_aci.power, s_aci.hidden);
	    mosquitto_publish(mosq_host, NULL, t, strlen(payload), payload, 1, NULL);

	    mosquitto_destroy(mosq_host);
            printf("reboot\n");
            system("reboot");
	    nvram_close(NVRAM_ID);
        }

        nvram_bufset(NVRAM_ID, "state", "0");
        nvram_commit(NVRAM_ID);

        nvram_close(NVRAM_ID);
    }
    else if(strstr(message->topic, "/state") != 0) {
        char payload[512];
        mosquitto_log(payload);

        mosquitto_publish(mosq, NULL, topic.state_pvs, strlen(payload), payload, 1, NULL);
    }
    fflush(stdout);
}

void check_opmode_and_Get_IP(){
   nvram_init(NVRAM_ID);

   const char *opmode = NULL;
   opmode = nvram_bufget(NVRAM_ID, "OperationMode");
   if(!strcmp(opmode, "0")) {
      printf("OP mode!!\n");
      system("udhcpc -i br0 -s /sbin/udhcpc.sh -p /var/run/udhcp");
   }
   nvram_close(NVRAM_ID);
}

void my_connect_callback(struct mosquitto *mosq, void *userdata, int result) {
    if(!result) {
        /* Subscribe to broker information topics on successful connect. */
        char temp[40] = {0,};
        sprintf(temp, "PVS/server/fw_up/%s", mac_address);
        mosquitto_subscribe(mosq, NULL, temp, 1);
        sprintf(temp, "PVS/server/config/%s", mac_address);
        mosquitto_subscribe(mosq, NULL, temp, 1);
    }
    else {
        fprintf(stderr, "Connect failed\n");
    }
}

void make_topic() {
    char temp[64] = {0,};

    memset(&temp, 0x00, 64);
    sprintf(temp, "PVS/device/log/%s", mac_address);
    strncpy(topic.log, temp, strlen(temp));

    memset(&temp, 0x00, 64);
    sprintf(temp, "PVS/device/state/%s", mac_address);
    strncpy(topic.state_pvs, temp, strlen(temp));

    memset(&temp, 0x00, 64);
    sprintf(temp, "PVS/device/fw_up/%s", mac_address);
    strncpy(topic.fw_up, temp, strlen(temp));

    memset(&temp, 0x00, 64);
    sprintf(temp, "PVS/device/config/%s", mac_address);
    strncpy(topic.config_pvs, temp, strlen(temp));

    memset(&temp, 0x00, 64);
    sprintf(temp, "PVS/device/error/%s", mac_address);
    strncpy(topic.error, temp, strlen(temp));

	memset(&temp, 0x00, 64);
    sprintf(temp, "PVS/PING/%s", mac_address);
    strncpy(topic.ping, temp, strlen(temp));
}

void mosquitto_log(char *payload) {
    
    const char *rt_code, *state, *op_mode, *config_ver, *hidden;
//    char model_name[255] = {0,}, booting_num[10] = {0,};
    const char *model_name, *booting_num;
//    char ssid[255] = {0,}, hidden, password[255] = {0,}, wifi_mode[10] = {0,}, channel[10] = {0,}, bandwidth[10] = {0,}, txpower[10] = {0,};
    const char *ssid, *password, *wifi_mode, *channel, *bandwidth, *txpower;
    char uptime[20] = { 0, }, free_mem[10] = { 0, }, fw_ver[8] = { 0, };
//    const char *uptime, *free_mem, *fw_ver;

    rt_code = "0";

    op_mode = nvram_bufget(NVRAM_ID, "OperationMode");
    model_name = nvram_bufget(NVRAM_ID, "model_name");
//    fw_ver = nvram_bufget(NVRAM_ID, "fw_ver");
    get_fw_ver(&fw_ver[0]);
    config_ver = nvram_bufget(NVRAM_ID, "config_ver");
    
    state = nvram_bufget(NVRAM_ID, "state");

    get_data_basic(uptime, "exec uptime | awk '{print$3}'");
    uptime[strlen(uptime) - 1] = '\0';
    get_data_basic(free_mem, "exec free | grep Mem | awk '{print$4}'");
    free_mem[strlen(free_mem) - 1] = '\0';

    booting_num = nvram_bufget(NVRAM_ID, "booting_num");
    ssid = nvram_bufget(NVRAM_ID, "SSID1");
    hidden = nvram_bufget(NVRAM_ID, "HideSSID");
    password = nvram_bufget(NVRAM_ID, "WPAPSK1");
    wifi_mode = nvram_bufget(NVRAM_ID, "WirelessMode");
    channel = nvram_bufget(NVRAM_ID, "Channel");
    bandwidth = nvram_bufget(NVRAM_ID, "HT_BW");

    txpower = nvram_bufget(NVRAM_ID, "TxPower");
    sprintf(payload,"{\"mac\":\"%s\",\"rt_code\":\"%s\",\"op_mode\":\"%s\",\"model_name\":\"%s\",\"fw_ver\":\"%s\",\"config_ver\":\"%s\",\"state\":\"%s\",\"uptime\":\"%s\",\"free_mem\":\"%s\",\"booting_num\":\"%s\",\"ssid\":\"%s\",\"hidden\":\"%s\",\"password\":\"%s\",\"mode\":\"%s\",\"channel\":\"%s\",\"bandwidth\":\"%s\",\"txpower\":\"%s\"}"
                    , mac_address, rt_code, op_mode, model_name, fw_ver, config_ver, state, uptime, free_mem, booting_num, ssid, hidden, password, wifi_mode, channel, bandwidth, txpower);
    printf("payload = %s\n", payload);
}

int get_fw_ver(char *value)
{
        FILE *fp;
        char buffer[128]={0,};
        char model_type[128]={0,};
        char version[8]={0,};


        fp = fopen("/etc_ro/version", "r");
        if(fp != NULL)
        {
                fgets(buffer, sizeof(buffer), fp);
                fclose(fp);
                sscanf(buffer,"%s %s", model_type, version);
                strcpy(value,version);
                printf("get_fw_ver : %s \n",value);
        }
        else
                strcpy(value,"Unknown");
        return 0;
}

int main(int argc, char *argv[])
{
    	char host[16];
	int port = 1883;
	int keepalive = 60;
	bool clean_session = true;

	get_data_basic(mac_address, "exec ifconfig br0 | grep -r HWaddr | awk '{print$5}'");
	mac_address[strlen(mac_address) - 1] = '\0';

	mosquitto_lib_init();
	mosq = mosquitto_new(NULL, clean_session, NULL);
	if(!mosq) {
		fprintf(stderr, "Error: Out of memory.\n");
		return;
	}

	mosquitto_connect_callback_set(mosq, my_connect_callback);
    while(1) {
        if(mosquitto_connect(mosq, "www.baruntechpvs.com", port, keepalive)) {
            fprintf(stderr, "Unable to connect.\n");
            sleep(3);
        }
        else break;
    }

	mosquitto_message_callback_set(mosq, my_message_callback);

    make_topic();
    //check_opmode_and_Get_IP();
    char payload[512];
    mosquitto_log(payload);

    printf("payload = %s\n", payload);
    mosquitto_publish(mosq, NULL, topic.log, strlen(payload), payload, 1, NULL);

	char alivecmd[255] = {0,};
	char alivetmp[255] = {0,};
	strcpy(alivetmp, mac_address);
	escapeStr(alivetmp);
	sprintf(alivecmd, "alive:%s", alivetmp);
	mosquitto_publish(mosq, NULL, topic.ping, strlen(alivecmd), alivecmd, 1, NULL);

    if(!strcmp(nvram_bufget(NVRAM_ID, "state"), "2")) {
        mosquitto_publish(mosq, NULL, topic.config_pvs, strlen(""), "", 1, NULL);
    }
    else if(!strcmp(nvram_bufget(NVRAM_ID, "state"), "3")) {
        nvram_bufset(NVRAM_ID, "state", "0");
    }
    else {
        mosquitto_publish(mosq, NULL, topic.fw_up, strlen(""), "", 1, NULL);
    }


	signal(SIGALRM,(void*)sigint_handler);
	alarm(atoi(nvram_bufget(NVRAM_ID, "pvs_period")));

    //nvram_bufget(nvram_num, "booting_num");

    mosquitto_loop_forever(mosq, -1, 1);

    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    return 0;
}
