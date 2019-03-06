#!/bin/bash
#
# version 0.0.2


### SET DEFAULTS HERE ###


### END DEFAULTS ###

shopt -s -o nounset
declare -rx SCRIPT=${0##*/}

if [ $# -eq 0 ] ; then
  printf "%s\n" "Type --help for help."
  exit 192
fi

# Proccess paramaters

while [ $# -gt 0 ] ; do
  case "$1" in
    -h | --help)
      echo ""
      printf "%s\n" "usage: $SCRIPT -f <qkview location> -b [yes|no] "
      printf "%s\n" "-f location of qkview file"
      printf "%s\n" "-b backup before import [yes|no] default no"
      printf "%s\n" "-h --help"
      printf "%s\n\n" ""
      printf "%s\n" "Example:"
      printf "%s\n\n" "$SCRIPT -f /var/tmp/support_file.qkview -b no"

      exit 0
      ;;

    -b ) shift
      if [ $# -eq 0 ] ; then
        printf "$SCRIPT:$LINENO: %s\n" "-b requires arg [yes|no]" >&2
        exit 192
        fi
        backUp="$1"
        ;;


    -f ) shift
      if [ $# -eq 0 ] ; then
        printf "$SCRIPT:$LINENO: %s\n"  "Missing file location" >&2
        exit 192
        fi
        fileLocation="$1"
        ;;


    -* ) printf "$SCRIPT:$LINENO: %s\n"  "switch $1 not supported" >&2
      exit 192
      ;;


    * ) printf "$SCRIPT:$LINENO: %s\n"  "extra argument or missing switch" >&2
      exit 192
      ;;


  esac
  shift
done


## functions ##

check_if_fileLocation_empty () {
  if [ -z $fileLocation ]; then
  echo "qkview source file not given"
  exit 1
  fi
}

check_source_file_found () {
  if [ ! -f $fileLocation ]; then
    echo "qkview file $fileLocation not found"
    exit 0
  fi
}


main ()
{
check_if_fileLocation_empty
check_source_file_found

}
main "$@"

