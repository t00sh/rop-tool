#!/bin/sh

TEST_DIR="./test/"

function usage() {
    echo "Usage : $1 [OPTIONS]"
    echo "   -h           help"
    echo "   -t           Run tests"
    echo "   -a <test>    Add test"
    echo "   -u           Update tests"
    echo "   -U <test>    Update a single test"
}

function report_bad_test() {

    echo "[-] Test failed !"
    echo "[-] $1 differe in command \"" $(cat $TEST_DIR/$2.sh) "\" ($2.sh)"
    printf "\n\n\n\n"
}

function run_tests() {
    i=1
    for F in $TEST_DIR/*.sh
    do
	FILE=$(basename $F .${F##*.})
	echo "[+] Run test number $i.....$FILE.....$(cat $TEST_DIR/$FILE.sh)"
	
	bash $TEST_DIR/$FILE.sh 1>/tmp/$FILE.stdout 2>/tmp/$FILE.stderr

	if test -f $TEST_DIR/$FILE.stdout
	then
	    diff -u $TEST_DIR/$FILE.stdout /tmp/$FILE.stdout || report_bad_test stdout $FILE
	fi

	if test -f $TEST_DIR/$FILE.stderr
	then
	    diff -u $TEST_DIR/$FILE.stderr /tmp/$FILE.stderr || report_bad_test stderr $FILE
	fi
	
	i=$(($i+1))
    done
}

function add_test() {
    i=0

    while test -f $TEST_DIR/test$i".sh"
    do
	i=$(($i + 1))
    done

    FILE=$TEST_DIR/test$i
    
    echo $1 > $FILE.sh

    bash $FILE.sh 1>$FILE.stdout 2>$FILE.stderr

    echo "[+] Test $FILE.sh added !"
}

function update_test() {
    if test ! -f $1.sh
    then
	echo "[-] $1.sh doesn't exist !"
	exit 1
    fi
    bash $1.sh 1>$1.stdout 2>$1.stderr
    echo "[+] $1 updated"
}

function update_tests() {


    rm $TEST_DIR/*.stderr
    rm $TEST_DIR/*.stdout
    
    for F in $TEST_DIR/*.sh
    do
	FILE=$(basename $F .${F##*.})
	update_test $TEST_DIR/$FILE
	
    done
}

while getopts "hta:uU:" opt
do
    case $opt in
	"h")
	    usage $0
	    exit 1
	    ;;
	"t")
	    run_tests
	    exit 0
	    ;;
	"a")
	    add_test "$(echo $* | sed 's/\-a //')"
	    exit 0
	    ;;
	"u")
	    update_tests
	    exit 0
	    ;;
	"U")
	    update_test $OPTARG
	    exit 0
	    ;;
	*)
	    usage $0
	    exit 1
	    ;;
    esac
done

usage $0
exit 1
