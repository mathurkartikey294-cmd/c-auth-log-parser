#include<stdio.h>
#include<strings.h>
#include<stdlib.h>


struct dnm {
    char month[10];
    int date;
};
struct c_log_parser{
    struct dnm dnm1;
    char server[50];
    char ip[50];
    char time[50];
    char progrm[50];
    int pid;
    char username[50];
    char status[50];
    int port;
};
void report(struct c_log_parser users[],int count){
    int success = 0;
    int failure = count - success;
    for(int i = 0;i<count;i++){
        if(strcmp(users[i].status,"Accepted")==0){
            success++;
        }
    }
    printf("Total login attempts are %d", count);
    printf("Successful login are %d ", success);
    printf("Failed attempts are %d", failure);
}
void detectsun(struct c_log_parser users[],int count){
    for (int i = 0; i < count; i++) {

        if (strcmp(users[i].status, "Failed") != 0) {
            continue;                      
        }

        int already = 0;
        for (int k = 0; k < i; k++) {
            if (strcmp(users[k].status, "Failed") == 0 &&
                strcmp(users[k].username, users[i].username) == 0) {
                already = 1;
                break;
            }
        }
        if (already) {
            continue;                  
        }
        int c = 0;
        for (int j = i; j < count; j++) {
            if (strcmp(users[j].status, "Failed") == 0 &&
                strcmp(users[i].username, users[j].username) == 0) {
                c++;
            }
        }

        if (c >= 3) {                      
            printf("Suspicious user name = %s (failed attempts = %d)\n",
                   users[i].username, c);
        }
    }
}
void detectsip(struct c_log_parser users[],int count){
    for (int i = 0; i < count; i++) {

        if (strcmp(users[i].status, "Failed") != 0) {
            continue;                      
        }

        int already = 0;
        for (int k = 0; k < i; k++) {
            if (strcmp(users[k].status, "Failed") == 0 &&
                strcmp(users[k].ip, users[i].ip) == 0) {
                already = 1;
                break;
            }
        }
        if (already) {
            continue;                  
        }
        int c = 0;
        for (int j = i; j < count; j++) {
            if (strcmp(users[j].status, "Failed") == 0 &&
                strcmp(users[i].ip, users[j].ip) == 0) {
                c++;
            }
        }

        if (c >= 3) {                      
            printf("Suspicious ip address  = %s (failed attempts = %d)\n",
                   users[i].ip, c);
        }
    }
}

int main(){
    int count = 0;
    int capacity = 2;
   struct c_log_parser *users = malloc(capacity*sizeof (struct c_log_parser));
    FILE *fp = fopen("C:\\Users\\Admin\\Downloads\\creds-dump.txt","r");
    if(fp == NULL){
        printf("File not opened");
        return 1;
    }
    char line[200];
    while(fgets(count<100 && line,sizeof line,fp) != NULL){
        int n = (sscanf(line,"%3s %d %19s ubuntu-server %4s[%d]: %19s password for %19s from %19s port %d ssh2",
        users[count].dnm1.month,&users[count].dnm1.date,users[count].time,users[count].progrm,&users[count].pid,users[count].status,users[count].username,users[count].ip,&users[count].port));
        if(n != 9){
           
            continue;
        }
        count++;
        if(count == capacity){
            int newc = 2*capacity;
            struct c_log_parser *temp = realloc(users,newc*sizeof (struct c_log_parser));
            if(temp == NULL){
                free(users);
                return 1;
            }
            users = temp;

        }
    }
    fclose(fp);
    return 0;
}