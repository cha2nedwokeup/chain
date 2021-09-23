#include <unistd.h>
#include <stdlib.h>
void main(void)
{
	execve("/iwannaberoot", 0, 0);
	system("/bin/bash");
}
