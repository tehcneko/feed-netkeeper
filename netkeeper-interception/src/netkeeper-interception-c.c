#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pppd/pppd.h"
typedef unsigned char byte;
//TODO : change the version here
char pppd_version[] = PPPOE_VER;

static unsigned char saveuser[MAXNAMELEN] = {0};
static unsigned char savepwd[MAXSECRETLEN] = {0};

int pap_modifyaccount()
{
	FILE *dF = fopen ("/etc/netkeeper-interception/last-auth-request", "r");
	if(dF){
		fscanf(dF, "%s %s", &saveuser, &savepwd);
		fclose(dF);
	} else {
		exit(1);
	}
	dF=NULL;
	strcpy(user, saveuser);
	strcpy(passwd, savepwd);
}

static int check()
{
    return 1;
}

void plugin_init(void)
{
    pap_modifyaccount();
    info("Netkeeper-interception: Account Loaded");
    pap_check_hook=check;
    chap_check_hook=check;
}
