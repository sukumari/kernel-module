#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 256 
 
struct packet_data {
    int type_of_packet;
    unsigned short int sport;
    unsigned short int dport;
    unsigned int src_ip;
    unsigned int dest_ip;
};

const char* packet_type_name(int type_of_packet) {
    if (type_of_packet == 6) {
        return "TCP";
    }
    return "IP PACKET";
}
            
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
   
    struct packet_data pd;
    memset(&pd, 0, sizeof(pd)); 
    
    while (num_of_packet > 0) {
       sleep(3);  
       ret = read(fd, &pd, sizeof(struct packet_data));
       
       if (ret < 0) {
           perror("Failed to read the message from the device.");
           return errno;
       }
       
       printf("packet [%d] details :\n packet_type = %s, sport = %d, dport = %d, ",
                                    num_of_packet, packet_type_name(pd.type_of_packet), pd.sport, pd.dport);

       printf("src_ip = %d.%d.%d.%d, ", pd.src_ip & 0xFF, 
                                        pd.src_ip >> 8 & 0xFF,
       				                    pd.src_ip >> 16 & 0xFF,
                                        pd.src_ip >> 24 & 0xFF);

       printf("dest_ip = %d.%d.%d.%d\n", pd.dest_ip & 0xFF,
       				                    pd.dest_ip >> 8 & 0xFF,
       				                    pd.dest_ip >> 16 & 0xFF,
       				                    pd.dest_ip >> 24 & 0xFF);
       				
       --num_of_packet;
   }
   
   printf("End of the program\n");
   
   return 0;
}
