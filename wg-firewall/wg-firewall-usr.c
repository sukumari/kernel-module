#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 256 
 
struct ip_packet_info {
    unsigned short int sport;
    unsigned short int dport;
    unsigned int src_ip;
    unsigned int dest_ip;
    
};
            
int main(){
    int ret, fd;
    char send_buf[BUFFER_LENGTH];
    
    printf("Lets test wgfilter device\n");
   
    fd = open("/dev/wgfilter", O_RDWR);
   
    if (fd < 0){
        perror("Failed to open the device...");
        return errno;
    }

    printf("Enter number of packet info you want to see :\n");
    scanf("%[^\n]%*c", send_buf);
    printf("Writing message to the device [%s].\n", send_buf);
    
    ret = write(fd, send_buf, strlen(send_buf));
    if (ret < 0) {
        perror("Failed to write the message to the device.");
        return errno;
    }
    
    int num_of_packet = atoi(send_buf);
    
    printf("Press ENTER to read back from the device...\n");
    getchar();
 
    printf("Reading from the device...\n");
   
    struct ip_packet_info info;
    memset(&info, 0, sizeof(info)); 
    
    while (num_of_packet > 0) {
       sleep(3);  
       ret = read(fd, &info, sizeof(struct ip_packet_info));
       
       if (ret < 0) {
           perror("Failed to read the message from the device.");
           return errno;
       }
       
       printf("packet [%d] details :\n sport = %d, dport = %d, ", num_of_packet, info.sport, info.dport);
       printf("src_ip = %d.%d.%d.%d, ", info.src_ip & 0xFF
       				    , info.src_ip >> 8 & 0xFF
       				    , info.src_ip >> 16 & 0xFF
       				    , info.src_ip >> 24 & 0xFF);
       printf("dest_ip = %d.%d.%d.%d\n", info.dest_ip & 0xFF
       				    , info.dest_ip >> 8 & 0xFF
       				    , info.dest_ip >> 16 & 0xFF
       				    , info.dest_ip >> 24 & 0xFF);
       				
       --num_of_packet;
   }
   
   printf("End of the program\n");
   
   return 0;
}
