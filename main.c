#include<stdio.h>
#include<string.h>
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
void report(struct c_log_parser users[],int count,FILE *fp){
    int success = 0;
   
    for(int i = 0;i<count;i++){
        if(strcmp(users[i].status,"Accepted")==0){
            success++;
        }
    }
     int failure = count - success;
     fprintf(fp, "    \"login_attempts\": %d,\n", count);
    fprintf(fp, "    \"successful_logins\": %d,\n", success);
    fprintf(fp, "    \"failed_attempts\": %d", failure);
}
int tts(char c[]){
    int h,m,s;
    sscanf(c,"%d:%d:%d",&h,&m,&s);
    int seconds = h*3600 + m*60 + s;
    return seconds;
}
void detectsun(struct c_log_parser users[], int count, FILE *fp)
{
    fprintf(fp, "    \"suspicious_users\": [\n");
    int first = 1;
    for (int i = 0; i < count; i++)
    {
        if (strcmp(users[i].status, "Failed") != 0)
            continue;
        int already = 0;
        for (int k = 0; k < i; k++)
        {
            if (strcmp(users[k].status, "Failed") == 0 &&
                strcmp(users[k].username, users[i].username) == 0)
            {
                already = 1;
                break;
            }
        }
        if (already)
            continue;
        int c = 0;
        for (int j = i; j < count; j++)
        {
            int a = tts(users[i].time);
            int b = tts(users[j].time);
            if (strcmp(users[j].status, "Failed") == 0 &&
                strcmp(users[i].username, users[j].username) == 0 &&
                (b - a) <= 10 &&
                users[i].dnm1.date == users[j].dnm1.date &&
                strcmp(users[i].dnm1.month, users[j].dnm1.month) == 0)
            {
                c++;
            }
        }

        if (c >= 3)
        {
            if (!first)
                fprintf(fp, ",\n");

            fprintf(fp,
                "        {\n"
                "            \"username\": \"%s\",\n"
                "            \"failed_attempts\": %d,\n"
                "            \"ip\": \"%s\",\n"
                "            \"event\": \"%s\",\n"
                "            \"port\": %d,\n"
                "            \"pid\": %d\n"
                "        }",
                users[i].username,
                c,
                users[i].ip,
                users[i].progrm,
                users[i].port,
                users[i].pid
            );
            first = 0;
        }
    }
    fprintf(fp, "\n    ]");
}
void detectsip(struct c_log_parser users[], int count, FILE *fp)
{
    fprintf(fp, "    \"suspicious_ips\": [\n");
    int first = 1;
    for (int i = 0; i < count; i++)
    {
        if (strcmp(users[i].status, "Failed") != 0)
            continue;
        int already = 0;
        for (int k = 0; k < i; k++)
        {
            if (strcmp(users[k].status, "Failed") == 0 &&
                strcmp(users[k].ip, users[i].ip) == 0)
            {
                already = 1;
                break;
            }
        }
        if (already)
            continue;
        int c = 0;
        for (int j = i; j < count; j++)
        {
            int a = tts(users[i].time);
            int b = tts(users[j].time);
            if (strcmp(users[j].status, "Failed") == 0 &&
                strcmp(users[i].ip, users[j].ip) == 0 &&
                (b - a) <= 10 &&
                users[i].dnm1.date == users[j].dnm1.date &&
                strcmp(users[i].dnm1.month, users[j].dnm1.month) == 0)
            {
                c++;
            }
        }
        if (c >= 3)
        {
            if (!first)
                fprintf(fp, ",\n");

            fprintf(fp,
                "        {\n"
                "            \"ip\": \"%s\",\n"
                "            \"failed_attempts\": %d,\n"
                "            \"username\": \"%s\",\n"
                "            \"event\": \"%s\",\n"
                "            \"port\": %d,\n"
                "            \"pid\": %d\n"
                "        }",
                users[i].ip,
                c,
                users[i].username,
                users[i].progrm,
                users[i].port,
                users[i].pid
            );
            first = 0;
        }
    }
    fprintf(fp, "\n    ]");
}
int export_json(struct c_log_parser users[], int count)
{
    printf("EXPORT FUNCTION CALLED\n");
    FILE *fp = fopen("final_output.json", "w");
    if (fp == NULL)
    {
        printf("Error opening output.json\n");
        return 1;
    }
     printf("FILE OPENED\n");
    fprintf(fp, "{\n");
    report(users, count, fp);
    fprintf(fp, ",\n");
    detectsun(users, count, fp);
    fprintf(fp, ",\n");
    detectsip(users, count, fp);
    fprintf(fp, "\n}\n");
    fclose(fp);
    return 0;
}

int main(int argc,char *argv[]){
     printf("MAIN STARTED\n");
    if(argc != 2){
        printf("Give the log file");
        return 1;
    }
     printf("ARGUMENT OK\n");
    int count = 0;
    int fl = 0;
    int capacity = 2;
   struct c_log_parser *users = malloc(capacity*sizeof (struct c_log_parser));
    FILE *fp = fopen(argv[1],"r");
   if (fp == NULL) {
    perror("fopen");
    return 1;
}
printf("file opened");
    char line[200];
    while(fgets( line,sizeof line,fp) != NULL){
        int n = (sscanf(line,"%3s %d %19s ubuntu-server %4s[%d]: %19s password for %19s from %19s port %d ssh2",
        users[fl].dnm1.month,&users[fl].dnm1.date,users[fl].time,users[fl].progrm,&users[fl].pid,users[fl].status,users[fl].username,users[fl].ip,&users[fl].port));
        count++;
        if(n != 9){
            continue;
        }
        fl++;
        if(fl == capacity){
            int newc = 2*capacity;
            struct c_log_parser *temp = realloc(users,newc*sizeof (struct c_log_parser));
            if(temp == NULL){
                free(users);
                return 1;
            }
            users = temp;
            capacity = newc;
        }
    }
    printf("reading finished");
    fclose(fp);
    printf("BEFORE EXPORT\n");
     export_json(users,count);
     printf("AFTER EXPORT\n");
    free(users);
    return 0;
}