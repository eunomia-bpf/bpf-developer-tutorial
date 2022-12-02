#ifndef ENTRY_H_
#define ENTRY_H_

// header only helpers for develop wasm app
#include "cJSON/cJSON.c"
#include "helpers.h"

#define MAX_ARGS 32

int main(int argc, char **argv);
int bpf_main(char *env_json, int str_len)
{
	cJSON *env = cJSON_Parse(env_json);
	if (!env)
	{
		printf("cJSON_Parse failed for env json args.");
        return 1;
	}
	if (!cJSON_IsArray(env)) {
        printf("env json args is not an array.");
        return 1;
    }
    int argc = cJSON_GetArraySize(env);
    if (argc > MAX_ARGS) {
        printf("env json args is too long.");
        return 1;
    }
    char *argv[MAX_ARGS];
    for (int i = 0; i < argc; i++) {
        cJSON *item = cJSON_GetArrayItem(env, i);
        if (!cJSON_IsString(item)) {
            printf("env json args is not a string.");
            return 1;
        }
        argv[i] = item->valuestring;
    }
	return main(argc, argv);
}

#endif
