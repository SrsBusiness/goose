# goose
Runtime dynamic memory checker written in Golang

## Only tested on x86_64 Linux version 4.9.137 ##

Demonstration:

test.c:
```c
#include <stdlib.h>
#include <stdio.h>

int main() {
    void *x1 = NULL, *x2, *x4, *x8, *x16;
    x1 = calloc(1, 1);
    x2 = calloc(2, 1);
    x4 = calloc(4, 1);
    x8 = calloc(8, 1);
    x16 = calloc(16, 1);
    x16 = realloc(x16, 32);
    free(x1);
    free(x2);
    free(x4);
    free(x8);
    free(x16);

    return 0;
}
```

```bash
$ make
go build -o goose *.go
$ gcc -o test test.c
$ ./goose ./test
Child pid: 6826
calloc(1, 1) -> 0x0000000001d6e010
calloc(2, 1) -> 0x0000000001d6e030
calloc(4, 1) -> 0x0000000001d6e050
calloc(8, 1) -> 0x0000000001d6e070
calloc(16, 1) -> 0x0000000001d6e090
realloc(0x0000000001d6e090, 32) -> 0x0000000001d6e090
free(0x0000000001d6e010)
free(0x0000000001d6e030)
free(0x0000000001d6e050)
free(0x0000000001d6e070)
free(0x0000000001d6e090)
Child exited 0
No memory errors!
```
