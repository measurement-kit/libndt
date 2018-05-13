/* Part of Measurement Kit <https://measurement-kit.github.io/>.
   Measurement Kit is free software under the BSD license. See AUTHORS
   and LICENSE for more information on the copying conditions. */
#ifndef STRTONUM_H
#define STRTONUM_H

#ifdef HAVE_STRTONUM
#include <stdlib.h>
#else
#ifdef __cplusplus
extern "C" {
#endif

long long strtonum(const char *numstr, long long minval, long long maxval,
                   const char **errstrp);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* HAVE_STRTONUM */
#endif /* STRTONUM_H */
