#include "stdlib.h"

unsigned char ** uniqueiv_init(void)
{
	int i;

	/* allocate root bucket (level 0) as vector of pointers */

	unsigned char ** uiv_root
		= (unsigned char **) malloc(256 * sizeof(unsigned char *));

	if (uiv_root == NULL) return (NULL);

	/* setup initial state as empty */

	for (i = 0; i < 256; ++i) uiv_root[i] = NULL;

	return (uiv_root);
}