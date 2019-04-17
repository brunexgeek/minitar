#include "minitar.h"
#include <stdio.h>

#define EXTRACT_CONTENT

int main( int argc, char **argv )
{
    mtar_t object;
    const mtar_header_t *header = NULL;

    if (argc != 2) return 1;

    if (mtar_open(&object, argv[1], MTAR_READ) == MTAR_ESUCCESS)
    {
        while (!mtar_eof(&object))
        {
            mtar_header(&object, &header);
            if (header->path[0] != 0)
                printf("%s/", header->path);
            printf("%s (%d bytes)\n", header->name, (uint32_t) header->size);
            mtar_next(&object);
        }
        mtar_close(&object);
    }

    return 1;
}