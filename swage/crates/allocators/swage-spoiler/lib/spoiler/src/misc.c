#include "../include/misc.h"

// Function that checks if we are running as root
int is_root()
{
	if (getuid() != 0)
	{
		return 0;
	}
	return 1;
}
