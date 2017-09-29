#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "json.h"

void process_object(json_value* value,char* obj, char* buf);
void process_value(json_value* value, char* obj, char* buf);
void process_array(json_value* value, char* obj, char* buf);
void get_json_data(char* data, char* obj, char* buf);