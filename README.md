# About minicrypt

This package will offer portable versions of common, old, and legacy crypto
functions that are being depricated and removed from crypto libraries. This
is being done in C to enable supporting legacy devices that may exist in the
field (such as VoIP phones) that may still be in active use.

These crypto functions may not be optimized, but they are meant for portability
and ease of use. This includes being able to reliably build endian neutral
functions. There is a linkable library built for efficiency, but it has a very
small footprint and each crypto function is made stand-alone. The goal is to
keep minicrypt small, simple, safe, and convient to use.

Minicrypt requires CMake and any modern C compiler to build it. There should be
no dependencies outside the libc standard library. Minicrypt  should build and
work with GCC (9 or later), with Clang (14? or later), and probably even with
MSVC.

## Distributions

Distributions of this package are provided as detached source tarballs made
from a tagged release from our internal source repository. These stand-alone
detached tarballs can be used to make packages for many GNU/Linux systems, and
for BSD ports. They may also be used to build and install the software directly
on a target platform.

## Participation

This project is offered as free (as in freedom) software for public use and has
a public home page at https://github.com/dyfet/minicrypt which has an issue
tracker where people can submit public bug reports, and a wiki for hosting
project documentation. We are not maintaining a public git repo nor do we have
any production or development related resources hosted on external sites.
Patches may be submitted and attached to an issue in the issue tracker. Support
requests and other kinds of inquiries may also be sent privately thru email to
tychosoft@gmail.com. Other details about participation may be found in the
Contributing page.

## Testing

There are testing programs for each header. These run simple tests that will be
expanded to improve code coverage over time. The test programs are the only
built target making this library by itself, and the test programs in this
package work with the cmake ctest framework. They may also be used as simple
examples of how a given header works. There is also a **lint** target that can
be used to verify code changes.
