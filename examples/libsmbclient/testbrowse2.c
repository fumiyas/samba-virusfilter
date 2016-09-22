/*
 * Alternate testbrowse utility provided by Mikhail Kshevetskiy.
 * This version tests use of multiple contexts.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libsmbclient.h>

int	debuglevel	= 0;
const char	*workgroup	= "NT";
const char	*username	= "guest";
const char	*password	= "";

typedef struct smbitem smbitem;
typedef int(*qsort_cmp)(const void *, const void *);

struct smbitem{
    smbitem	*next;
    int		type;
    char	name[1];
};

static void smbc_auth_fn(
                const char      *server,
		const char      *share,
		char            *wrkgrp, int wrkgrplen,
		char            *user,   int userlen,
		char            *passwd, int passwdlen){
		
    (void) server;
    (void) share;
    (void) wrkgrp;
    (void) wrkgrplen;

    strncpy(wrkgrp, workgroup, wrkgrplen - 1); wrkgrp[wrkgrplen - 1] = 0;
    strncpy(user, username, userlen - 1); user[userlen - 1] = 0;
    strncpy(passwd, password, passwdlen - 1); passwd[passwdlen - 1] = 0;
}

static SMBCCTX* create_smbctx(void){
    SMBCCTX	*ctx;

    if ((ctx = smbc_new_context()) == NULL) return NULL;

    smbc_setDebug(ctx, debuglevel);
    smbc_setFunctionAuthData(ctx, smbc_auth_fn);

    if (smbc_init_context(ctx) == NULL){
	smbc_free_context(ctx, 1);
	return NULL;
    }

    return ctx;
}

static void delete_smbctx(SMBCCTX* ctx){
    smbc_getFunctionPurgeCachedServers(ctx)(ctx);
    smbc_free_context(ctx, 1);
}

static smbitem* get_smbitem_list(SMBCCTX *ctx, char *smb_path){
    SMBCFILE		*fd;
    struct smbc_dirent	*dirent;
    smbitem		*list = NULL, *item;

    if ((fd = smbc_getFunctionOpendir(ctx)(ctx, smb_path)) == NULL)
        return NULL;
    while((dirent = smbc_getFunctionReaddir(ctx)(ctx, fd)) != NULL){
	size_t slen;
	if (strcmp(dirent->name, "") == 0) continue;
	if (strcmp(dirent->name, ".") == 0) continue;
	if (strcmp(dirent->name, "..") == 0) continue;
	
	slen = strlen(dirent->name)+1;
	if ((item = malloc(sizeof(smbitem) + slen)) == NULL)
	    continue;
	
	item->next = list;
	item->type = dirent->smbc_type;
	memcpy(item->name, dirent->name, slen);
	list = item;
    }
    smbc_getFunctionClose(ctx)(ctx, fd);
    return /* smbitem_list_sort */ (list);    
        
}

static void print_smb_path(const char *group, const char *path){
    if ((strlen(group) == 0) && (strlen(path) == 0)) printf("/\n");
    else if (strlen(path) == 0) printf("/%s\n", group);
    else{
	if (strlen(group) == 0) group = "(unknown_group)";
	printf("/%s/%s\n", group, path);
    }
}

static void recurse(SMBCCTX *ctx, const char *smb_group, char *smb_path, int maxlen){
    int 	len;
    smbitem	*list, *item;
    SMBCCTX	*ctx1;
    
    len = strlen(smb_path);
    
    list = get_smbitem_list(ctx, smb_path);
    while(list != NULL){
	switch(list->type){
	    case SMBC_WORKGROUP:
	    case SMBC_SERVER:
		if (list->type == SMBC_WORKGROUP){
		    print_smb_path(list->name, "");
		    smb_group = list->name;
		}
		else print_smb_path(smb_group, list->name);
		
		if (maxlen < 7 + strlen(list->name)) break;
		strncpy(smb_path + 6, list->name, maxlen - 6);
		smb_path[maxlen-1] = '\0';
		if ((ctx1 = create_smbctx()) != NULL){
		    recurse(ctx1, smb_group, smb_path, maxlen);
		    delete_smbctx(ctx1);
		}else{
		    recurse(ctx, smb_group, smb_path, maxlen);
		    smbc_getFunctionPurgeCachedServers(ctx)(ctx);
		}
		break;
	    case SMBC_FILE_SHARE:
	    case SMBC_DIR:
	    case SMBC_FILE:
		if (maxlen < len + strlen(list->name) + 2) break;
		
		smb_path[len] = '/';
		strncpy(smb_path + len + 1, list->name, maxlen - len - 1);
		smb_path[maxlen-1] = '\0';
		print_smb_path(smb_group, smb_path + 6);
		if (list->type != SMBC_FILE){
		    recurse(ctx, smb_group, smb_path, maxlen);
		    if (list->type == SMBC_FILE_SHARE)
			smbc_getFunctionPurgeCachedServers(ctx)(ctx);
		}
		break;
	}
	item = list;
	list = list->next;
	free(item);
    }
    smb_path[len] = '\0';
}

int main(int argc, char *argv[]){
    int		i;
    SMBCCTX	*ctx;
    char	smb_path[32768] = "smb://";

    if ((ctx = create_smbctx()) == NULL){
	perror("Cant create samba context.");
	return 1;
    }

    if (argc == 1) recurse(ctx, "", smb_path, sizeof(smb_path));
    else for(i = 1; i < argc; i++){
	strncpy(smb_path + 6, argv[i], sizeof(smb_path) - 7);
	smb_path[sizeof(smb_path) - 1] = '\0';
	recurse(ctx, "", smb_path, sizeof(smb_path));
    }
    
    delete_smbctx(ctx);
    return 0;	
}
