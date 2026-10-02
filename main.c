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
    char time[50];
    char progrm[50];
    int pid;
    char username[50];
    char status[50];
    int port;
};
int main(){
    FILE *fp = fopen("C:\\Users\\Admin\\Downloads\\creds-dump.txt","r");
    if(fp == NULL){
        printf("File not opened");
        return 1;
    }
    char line[200];
    while(fget(line,sizeof line,fp) != NULL){
        sscanf("%3s,%d,%19s,%49s,%[^[][,,")

    }
    return 0;
}