#ifndef __UTIL_H_
#define __UTIL_H_

#define PRINT_MAC_ADDRESS(F,X)  fprintf(F, \
                                        "%02X:%02X:%02X:%02X:%02X:%02X\n", \
                                        X[0],               \
                                        X[1],               \
                                        X[2],               \
                                        X[3],               \
                                        X[4],               \
                                        X[5]);
#define PRINT_IP_ADDRESS(F,X)   fprintf(F, "%02d.%02d.%02d.%02d\n", \
                                        X[0],               \
                                        X[1],               \
                                        X[2],               \
                                        X[3]);

#endif  // __UTIL_H_
