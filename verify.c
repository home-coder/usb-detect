#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <cutils/properties.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <cutils/klog.h>
#include "sha1.h"


#define VERIFY_LENGTH 20

#define ERROR(x...)   KLOG_ERROR("can", x)
#define NOTICE(x...)  KLOG_NOTICE("can", x)
#define INFO(x...)    KLOG_INFO("can", x)


const char code1[256] = {'r'- 0x7f, 'o'- 0x7f, '.' - 0x7f, 'b' - 0x7f, 'u' - 0x7f, 'i' - 0x7f, 'l' - 0x7f, 'd' - 0x7f,\
                  '.' - 0x7f, 'v' - 0x7f, 'e' - 0x7f, 'r' - 0x7f, 's' - 0x7f , 'i' - 0x7f, 'o' - 0x7f, 'n' - 0x7f,\
                  '.' - 0x7f, 'c' - 0x7f, 'h' - 0x7f, 'a' - 0x7f, 'n' - 0x7f, 'n' - 0x7f, 'e' - 0x7f , 'l' - 0x7f, 'i' - 0x7f, 'd' - 0x7f,\
                  0};

const char code2[256] = {'r'- 0x7f, 'o'- 0x7f, '.' - 0x7f, 'b' - 0x7f, 'u' - 0x7f, 'i' - 0x7f, 'l' - 0x7f, 'd' - 0x7f,\
                  '.' - 0x7f, 'd' - 0x7f, 'a' - 0x7f, 't' - 0x7f, 'e' - 0x7f,\
                  '.' - 0x7f, 'u' - 0x7f, 't' - 0x7f, 'c' - 0x7f,\
                  0};



int verify_file(FILE * fp)
{
    char buf[VERIFY_LENGTH] = { 0 };
    char codeSrc2[PROPERTY_VALUE_MAX] = { 0 };
    char verifySrc[PROPERTY_VALUE_MAX + PROPERTY_VALUE_MAX] = { 0 };
    char csum[VERIFY_LENGTH] = { 0 };
    char decode1[256] = { 0 };
    char decode2[256] = { 0 };
    char *p = NULL;
    int i = 0;
    
    if(VERIFY_LENGTH != fread(buf, 1, VERIFY_LENGTH, fp)){
        ERROR("verify fail,can not read enough data\n");
        return -1;
    }
    
    
    strcpy(decode1, code1);
    strcpy(decode2, code2);
     
    //decode property name 1
    for(p = decode1; *p; p++){
        *p += 0x7f;
    }
    
    property_get(decode1, verifySrc, "00000000");

    //decode property name 2
    for(p = decode2; *p; p++){
        *p += 0x7f;
    }

    property_get(decode2, codeSrc2, "00000000");

    strcat(verifySrc, codeSrc2);   

    ERROR("%s\n", verifySrc);

    sha1_csum(verifySrc, strlen(verifySrc), csum);
    if(memcmp(csum, buf, VERIFY_LENGTH)){
        ERROR("verify fail ...\n");
        ERROR("csum: ");
        for(i = 0;i < VERIFY_LENGTH; i++){
            ERROR("%02x", csum[i]);
        }
        ERROR("\n");
        ERROR("read: ");
        for(i = 0;i < VERIFY_LENGTH; i++){
            ERROR("%02x", buf[i]);
        }
        ERROR("\n");
        return -1;
    }
        
    ERROR("verify pass ...\n");
    return 0;
}

