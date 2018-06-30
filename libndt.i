/* Part of Measurement Kit <https://measurement-kit.github.io/>.
   Measurement Kit is free software under the BSD license. See AUTHORS
   and LICENSE for more information on the copying conditions. */

/*
 * SWIG interface file for libndt.
 */

%module(directors="1") libndt

%{
#include "libndt.hpp"
%}
 
%include "stl.i"
%include "stdint.i"
%include "std_string.i"

%feature("director") Client;

%template(StringMap) std::map<std::string, std::string>;
%ignore Err;

%rename("%(lowercamelcase)s", %$isfunction) "";
%rename("%(lowercamelcase)s", %$isvariable) "";

%include "libndt.hpp"
