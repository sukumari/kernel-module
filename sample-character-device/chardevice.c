#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/uaccess.h>          // Required for the copy to user function
#define  DEVICE_NAME "skchar"    ///< The device will appear at /dev/skchar using this value
#define  CLASS_NAME  "sk"        ///< The device class -- this is a character device driver
 
MODULE_LICENSE("GPL");            
MODULE_AUTHOR("Suman Kumari");    
MODULE_DESCRIPTION("A simple Linux char driver for the learning");  
MODULE_VERSION("0.1");            
 
static int    majorNumber;                  
static char   message[256] = {0};           
static short  size_of_message;              
static int    numberOpens = 0;              
static struct class*  skcharClass  = NULL; 
static struct device* skcharDevice = NULL; 

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
 

static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};

static int __init skchar_init(void){
   printk(KERN_INFO "SKChar: Initializing the SKChar LKM\n");
 
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "SKChar failed to register a major number\n");
      return majorNumber;
   }
   printk(KERN_INFO "SKChar: registered correctly with major number %d\n", majorNumber);
 
   skcharClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(skcharClass)){               
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(skcharClass);         
   }
   printk(KERN_INFO "SKChar: device class registered correctly\n");
 
   // Register the device driver
   skcharDevice = device_create(skcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(skcharDevice)){               
      class_destroy(skcharClass);          
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(skcharDevice);
   }
   printk(KERN_INFO "SKChar: device class created correctly\n"); 
   return 0;
}
 
 static void __exit skchar_exit(void){
   device_destroy(skcharClass, MKDEV(majorNumber, 0));    
   class_unregister(skcharClass);                         
   class_destroy(skcharClass);                            
   unregister_chrdev(majorNumber, DEVICE_NAME);            
   printk(KERN_INFO "SKChar: Goodbye from the LKM!\n");
}
 
static int dev_open(struct inode *inodep, struct file *filep){
   numberOpens++;
   printk(KERN_INFO "SKChar: Device has been opened %d time(s)\n", numberOpens);
   return 0;
}
 
 static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   error_count = copy_to_user(buffer, message, size_of_message);
 
   if (error_count==0){            
      printk(KERN_INFO "SKChar: Sent %d characters to the user\n", size_of_message);
      return (size_of_message=0); 
   }
   else {
      printk(KERN_INFO "SKChar: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;
   }
}
 

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   sprintf(message, "%s(%zu letters)", buffer, len);   
   size_of_message = strlen(message);
   printk(KERN_INFO "SKChar: Received %zu characters from the user\n", len);
   return len;
}

static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "SKChar: Device successfully closed\n");
   return 0;
}
 

module_init(skchar_init);
module_exit(skchar_exit);
