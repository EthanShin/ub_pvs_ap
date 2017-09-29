#include "parser.h"

void process_object(json_value* value,char* obj,char* buf)
{
        int length, x;
        if (value == NULL) {
                return;
        }
        length = value->u.object.length;
        for (x = 0; x < length; x++) 
      {
            if(strcmp(obj,value->u.object.values[x].name)==0)
         {
            printf("object[%d].name = %s\n", x, value->u.object.values[x].name);
            process_value(value->u.object.values[x].value, obj, buf);
            return;
         }
               
        }
}

void process_array(json_value* value, char* obj,char* buf)
{
        int length, x;
        if (value == NULL) {
                return;
        }
        length = value->u.array.length;
        for (x = 0; x < length; x++) {
                process_value(value->u.array.values[x], obj, buf);
        }
}

void process_value(json_value* value,char* obj,char* buf)
{
        int j;
        if (value == NULL) {
                return;
        }
      
        switch (value->type) {
                case json_none:
                        printf("none\n");
                        break;
                case json_object:
                        process_object(value, obj, buf);
                        break;
                case json_array:
                        process_array(value, obj, buf);
                        break;
                case json_integer:
                        printf("int: %10" PRId64 "\n", value->u.integer);
                        break;
                case json_double:
                        printf("double: %f\n", value->u.dbl);
                        break;
                case json_string:
                        printf("string: %s\n", value->u.string.ptr);
                  strcpy(buf,value->u.string.ptr);
                        break;
                case json_boolean:
                        printf("bool: %d\n", value->u.boolean);
                        break;
        }
}

void get_json_data(char* data,char* obj,char* buf)
{
   process_value((json_value*)json_parse((json_char*)data,strlen(data)),obj,buf);
   return;
}
