#ifndef DIE_H
#define DIE_H

#define __die0(fun) \
    do { \
        perror(#fun); \
        exit(EXIT_FAILURE); \
    } while(0)

#define __die1(fun, param) \
    do { \
        fprintf(stderr, #fun "(%s): %s\n", param, strerror(errno)); \
        exit(EXIT_FAILURE); \
    } while(0)

#endif
