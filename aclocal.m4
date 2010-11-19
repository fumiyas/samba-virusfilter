dnl AC_GET_MAKEFILE_VAR(FILE,VAR,VARPREFIX)
AC_DEFUN( [AC_GET_MAKEFILE_VAR],
[
	[$3$2=`perl -pe 's/\\\\\\n$//' "$1" |sed -n 's/^$2[ 	]*=[ 	]*\(.*\)/\1/p'`]
	AC_SUBST($3$2)
])

dnl AC_GET_DEFINED_VAR(FILE,VAR,VARPREFIX)
AC_DEFUN( [AC_GET_DEFINED_VAR],
[
	[$3$2=`sed -n 's/^#[ 	]*define[ 	][ 	]*$2[ 	][ 	]*\(.*\)/\1/p' "$1"`]
	AC_SUBST($3$2)
])
