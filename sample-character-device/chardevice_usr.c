#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
 
#define BUFFER_LENGTH 256             
static char rcv_buf[BUFFER_LENGTH];
 
int main(){
   int ret, fd;
   char send_buf[BUFFER_LENGTH];
   printf("Starting device test code example...\n");
   fd = open("/dev/skchar", O_RDWR);
   if (fd < 0){
      perror("Failed to open the device...");
      return errno;
   }
   printf("Type in a short string to send to the kernel module:\n");
   scanf("%[^\n]%*c", send_buf);
   printf("Writing message to the device [%s].\n", send_buf);
   ret = write(fd, send_buf, strlen(send_buf));
      if (ret < 0){
      perror("Failed to write the message to the device.");
      return errno;
   }
 
   printf("Press ENTER to read back from the device...\n");
   getchar();
 
   printf("Reading from the device...\n");
   ret = read(fd, rcv_buf, BUFFER_LENGTH);
   if (ret < 0){
      perror("Failed to read the message from the device.");
      return errno;
   }
   printf("The received message is: [%s]\n", rcv_buf);
   printf("End of the program\n");
   return 0;
}
